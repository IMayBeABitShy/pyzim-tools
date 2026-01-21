"""
Analyze compression of ZIM files.
"""
import argparse
import os
import statistics

from multiprocessing.pool import ThreadPool

import pyzim
from pyzim.util.iter import iter_by_cluster
from pyzim.cache import TopAccessCache, HybridCache
from pyzim.cluster import OffsetRememberingCluster
from pyzim.compression import CompressionType
from pyzim.pointerlist import OnDiskOrderedPointerList, OnDiskSimplePointerList, OnDiskTitlePointerList
import tqdm


POLICY = pyzim.policy.Policy(
    entry_cache_class=TopAccessCache,
    entry_cache_kwargs={"max_size": 2048},
    cluster_cache_class=HybridCache,
    cluster_cache_kwargs={"last_cache_size": 4, "top_cache_size": 4},
    cluster_class=OffsetRememberingCluster,
)
LOWRAM_POLICY = pyzim.policy.Policy(
    entry_cache_class=TopAccessCache,
    entry_cache_kwargs={"max_size": 2048},
    cluster_cache_class=HybridCache,
    cluster_cache_kwargs={"last_cache_size": 4, "top_cache_size": 2},
    cluster_class=OffsetRememberingCluster,

    simple_pointer_list_class=OnDiskSimplePointerList,
    ordered_pointer_list_class=OnDiskOrderedPointerList,
    title_pointer_list_class=OnDiskTitlePointerList,
)


def format_size(nbytes):
    """
    Format the given byte count into a human readable format.

    @param nbytes: size in bytes
    @type nbytes: L{int}
    @return: a human readable string describing the size
    @rtype: L{str}
    """
    for fmt in ("B", "KiB", "MiB", "GiB", "TiB"):
        if nbytes < 1024.0:
            return "{:.2f} {}".format(round(nbytes, 2), fmt)
        else:
            nbytes /= 1024.0
    return "{:.2f} PiB".format(round(nbytes, 2))


def set_or_increment(d, k, v):
    """
    Set or increment a value in a dict.

    If k not in d, set d[k] = v, else set d[k] = d[k] + v

    @param d: dictionary containing value to increase
    @type d: L{dict}
    @param k: key whose value should be increased
    @type k: hashable
    @param v: value to set/add to
    @type v: L{int} or L{float}
    """
    assert isinstance(d, dict)
    if k not in d:
        d[k] = v
    else:
        d[k] += v


def dict_sum(dicts):
    """
    Merge an iterable of dicts, summing the values for each key.

    @param dicts: iterable of dicts to merge
    @type dicts: iterable of L{dict}
    @return: a dict with the same keys and each value equal to the sums
    @rtype: L{dict}
    """
    result = {}
    for d in dicts:
        assert isinstance(d, dict)
        for key, value in d.items():
            set_or_increment(result, key, value)
    return result


def limit(iterable, n=None):
    """
    A generator function that only yields the first n entries.

    @param iterable: iterable to limit
    @type iterable: an iterable
    @param n: max amount of elements to yield, set to L{None} to yield all elements
    @type n: L{int} or L{None}
    """
    if n is None:
        yield from iterable
    elif n > 0:
        i = 0
        for e in iterable:
            yield e
            i += 1
            if i >= n:
                break


def analyze_group_compression(zim, urls):
    """
    Analyze the compression of a group of urls.

    @param zim: zim containing the entries to analyze
    @type zim: L{pyzim.archive.Zim}
    @param urls: list of (full) urls to analyze
    @type urls: L{list} of L{str}
    @return: a dict describing analysis results
    @rtype: L{dict}
    """
    entry_sizes_by_mimetype = {}
    entry_sizes_by_mainpath = {}
    entry_count_by_mimetype = {}
    entry_count_by_mainpath = {}
    content_sizes_by_mimetype = {}
    content_sizes_by_mainpath = {}
    cluster_count_by_mimetype_count = {}

    cluster_size = None
    cluster_compression_type = CompressionType.UNKNOWN
    cluster_entry_count = len(urls)
    for url in urls:
        entry = zim.get_entry_by_full_url(url)
        mimetype = entry.mimetype
        mainpath = url.split("/")[0][1:]

        if entry.is_redirect:
            # all remaining entries are redirects
            set_or_increment(entry_sizes_by_mimetype, "<redirect>", entry.get_disk_size())
            set_or_increment(entry_sizes_by_mainpath, mainpath, entry.get_disk_size())
            # set_or_increment(entry_count_by_mimetype, "<redirect>", 1)
            set_or_increment(entry_count_by_mainpath, mainpath, 1)
            continue

        cluster = entry.get_cluster()

        if cluster_size is None:
            cluster_size = cluster.get_content_size()
            cluster_compression_type = cluster.compression

        entry_size = entry.get_disk_size()
        content_size = entry.get_size()
        set_or_increment(entry_sizes_by_mimetype, mimetype, entry_size)
        set_or_increment(entry_sizes_by_mainpath, mainpath, entry_size)
        set_or_increment(content_sizes_by_mimetype, mimetype, content_size)
        set_or_increment(content_sizes_by_mainpath, mainpath, content_size)
        set_or_increment(entry_count_by_mimetype, mimetype, 1)
        set_or_increment(entry_count_by_mainpath, mainpath, 1)

    cluster_count_by_mimetype_count = {len(content_sizes_by_mimetype): 1}
    result = {
        "entry_sizes_by_mimetype": entry_sizes_by_mimetype,
        "entry_sizes_by_mainpath": entry_sizes_by_mainpath,
        "entry_count_by_mimetype": entry_count_by_mimetype,
        "entry_count_by_mainpath": entry_count_by_mainpath,
        "content_sizes_by_mimetype": content_sizes_by_mimetype,
        "content_sizes_by_mainpath": content_sizes_by_mainpath,
        "cluster_entry_count": cluster_entry_count,
        "cluster_compression_type": cluster_compression_type,
        "cluster_count_by_mimetype_count": cluster_count_by_mimetype_count,
    }
    if cluster_size is not None:
        result["total_cluster_size"] = cluster_size
    else:
        result["total_cluster_size"] = 0
    return result


def analyze_compression(path, lowram=False, n=None):
    """
    Analyze the compression of a ZIM file.

    @param path: path to ZIM file
    @type path: L{str}
    @param lowram: if nonzero, use a lowram policy for the ZIM
    @type lowram: L{bool}
    @param n: limit output to the first n elements
    @type n: L{int} or L{None}
    """

    compressed_size = os.stat(path).st_size

    if lowram:
        policy = LOWRAM_POLICY
    else:
        policy = POLICY

    print("Opening ZIM... ", end="", flush=True)
    with pyzim.Zim.open(path, policy=policy) as zim:
        print("Done.")
        total_cluster_count = zim.header.cluster_count
        print("Initiating pool... ", end="")
        pool = ThreadPool(processes=1)  # multiprocessing.cpu_count())
        print("Done.")
        print("Grouping entries by cluster... ", end="")
        result_parts = list(
            tqdm.tqdm(
                pool.imap_unordered(
                    lambda urls, zim=zim: analyze_group_compression(zim, urls),
                    iter_by_cluster(zim),
                ),
                desc="Analyzing groups...",
                total=total_cluster_count,
            )
        )

        entry_sizes_by_mimetype = dict_sum([r["entry_sizes_by_mimetype"] for r in result_parts])
        entry_sizes_by_mainpath = dict_sum([r["entry_sizes_by_mainpath"] for r in result_parts])
        entry_count_by_mimetype = dict_sum([r["entry_count_by_mimetype"] for r in result_parts])
        entry_count_by_mainpath = dict_sum([r["entry_count_by_mainpath"] for r in result_parts])
        content_sizes_by_mimetype = dict_sum([r["content_sizes_by_mimetype"] for r in result_parts])
        content_sizes_by_mainpath = dict_sum([r["content_sizes_by_mainpath"] for r in result_parts])
        cluster_count_by_mimetype_count = dict_sum([r["cluster_count_by_mimetype_count"] for r in result_parts])
        total_cluster_size = sum([r["total_cluster_size"] for r in result_parts])
        cluster_entry_counts = [r["cluster_entry_count"] for r in result_parts]
        cluster_compression_types_raw = [r["cluster_compression_type"] for r in result_parts]
        cluster_compression_types = {ct: cluster_compression_types_raw.count(ct) for ct in cluster_compression_types_raw}

    total_entry_size = sum([v for v in entry_sizes_by_mimetype.values()])
    total_entry_count = sum([v for v in entry_count_by_mainpath.values()])  # not mimetype to keep track of redirects
    total_content_size = sum([v for v in content_sizes_by_mimetype.values()])
    total_size = total_entry_size + total_cluster_size

    print("===== Overall =====")
    print("Counts:")
    print(f" -> Entries: {total_entry_count}")
    print(f" -> Clusters: {total_cluster_count}")
    print(f" -> Mimetypes: {len(entry_count_by_mimetype) - 1}")
    print(f"Total size: {format_size(total_size)}")
    print(f" -> Entries: {format_size(total_entry_size)} ({total_entry_size/total_size:.2%})")
    print(f" -> Clusters: {format_size(total_cluster_size)} ({total_cluster_size/total_size:.2%})")
    print(f"Compressed Size: {format_size(compressed_size)} ({compressed_size/total_size:.2%})")

    print("==== Used compression types ===")
    for ct in limit(sorted(cluster_compression_types.keys(), key=lambda x: cluster_compression_types[x], reverse=True), n):
        amounts = cluster_compression_types[ct]
        print(f"{ct.name}: {amounts} ({amounts/total_cluster_count:.2%})")

    print("==== Entry count by mimetype ===")
    for mimetype in limit(sorted(entry_count_by_mimetype.keys(), key=lambda x: entry_count_by_mimetype[x], reverse=True), n):
        cnt = entry_count_by_mimetype[mimetype]
        print(f"{mimetype}: {cnt} ({cnt/total_entry_count:.2%})")

    print("==== Entry size by mimetype ===")
    for mimetype in limit(sorted(entry_sizes_by_mimetype.keys(), key=lambda x: entry_sizes_by_mimetype[x], reverse=True), n):
        size = entry_sizes_by_mimetype[mimetype]
        print(f"{mimetype}: {format_size(size)} ({size/total_entry_size:.2%})")

    print("==== Content size by mimetype ===")
    for mimetype in limit(sorted(content_sizes_by_mimetype.keys(), key=lambda x: content_sizes_by_mimetype[x], reverse=True), n):
        size = content_sizes_by_mimetype[mimetype]
        print(f"{mimetype}: {format_size(size)} ({size/total_content_size:.2%})")

    print("==== Entry count by mainpath ===")
    for mainpath in limit(sorted(entry_count_by_mainpath.keys(), key=lambda x: entry_count_by_mainpath[x], reverse=True), n):
        cnt = entry_count_by_mainpath[mainpath]
        print(f"{mainpath}: {cnt} ({cnt/total_entry_count:.2%})")

    print("==== Entry size by mainpath ===")
    for mainpath in limit(sorted(entry_sizes_by_mainpath.keys(), key=lambda x: entry_sizes_by_mainpath[x], reverse=True), n):
        size = entry_sizes_by_mainpath[mainpath]
        print(f"{mainpath}: {format_size(size)} ({size/total_entry_size:.2%})")

    print("==== Content size by mainpath ===")
    for mainpath in limit(sorted(content_sizes_by_mainpath.keys(), key=lambda x: content_sizes_by_mainpath[x], reverse=True), n):
        size = content_sizes_by_mainpath[mainpath]
        print(f"{mainpath}: {format_size(size)} ({size/total_content_size:.2%})")

    print("==== Entries per cluster ===")
    print(f"Min:  {min(cluster_entry_counts)}")
    print(f"Max:  {max(cluster_entry_counts)}")
    print(f"Mean: {statistics.mean(cluster_entry_counts)}")
    print(f"Median: {statistics.median(cluster_entry_counts)}")

    print("=== Mimetypes per cluster ===")
    mimetype_counts = list(cluster_count_by_mimetype_count.keys())
    expanded_mimetype_counts = []
    for mtc in sorted(mimetype_counts):
        cc = cluster_count_by_mimetype_count[mtc]
        expanded_mimetype_counts += ([mtc] * cc)
        print(f"{mtc}:     {cc}")
    print(f"Min:  {min(expanded_mimetype_counts)}")
    print(f"Max:  {max(expanded_mimetype_counts)}")
    print(f"Mean: {statistics.mean(expanded_mimetype_counts)}")
    print(f"Median: {statistics.median(expanded_mimetype_counts)}")


def main():
    """
    The main function.
    """
    parser = argparse.ArgumentParser(
        description="Analyze ZIM compression",
    )
    parser.add_argument(
        "--lowram",
        action="store_true",
        dest="lowram",
        help="Try to reduce RAM usage at performance cost",
    )
    parser.add_argument(
        "--limit",
        action="store",
        dest="limit",
        type=int,
        default=None,
        help="Print only the first x items for each list",
    )
    parser.add_argument(
        "zimpath",
        help="path to ZIM file",
    )
    ns = parser.parse_args()

    zimpath = ns.zimpath

    analyze_compression(zimpath, lowram=ns.lowram, n=ns.limit)


if __name__ == "__main__":
    main()

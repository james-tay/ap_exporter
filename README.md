# ap_exporter
Wifi AP metrics exporter for prometheus

The `ap_exporter.py` script connects to an FS Access Point using SSH and then
obtains various metrics by executing `show xxx` commands as instructed by the
helper scripts.

Since you need to run the `ap_exporter.py` script on a particular host, it is
necessary to include a `metric_relabel_configs` block in prometheus. In the
following example, `ap_exporter.py` runs on the host `deskbox` and is used
to obtain metrics from `fs-ap1`.

```
  - job_name: 'wifi'
    scrape_interval: 60s
    static_configs:
    - targets:
      - deskbox:8080
    metric_relabel_configs:
      - source_labels: [instance]
        target_label: instance
        replacement: 'fs-ap1'
```

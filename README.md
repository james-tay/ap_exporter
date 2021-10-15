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

Prometheus queries can be performed using curl. For example, the following
query lists the RSSIs of all currently connected clients :

```
  curl http://prometheus:9090/api/v1/query?query=wifi_client_Rssi
  {
    "status": "success",
    "data": {
      "resultType": "vector",
      "result": [
        {
          "metric": {
            "__name__": "wifi_client_Rssi",
            "chan": "149",
            "fqdn": "ecobee.drowningfrog.homenet.org",
            "instance": "fs-ap1",
            "ipaddr": "192.168.7.15",
            "job": "wifi",
            "macaddr": "44:61:32:c2:83:0d",
            "wlan_id": "3"
          },
          "value": [
            1634169609.477,
            "47"
          ]
        },
        ...
      ]
    }
  }
```


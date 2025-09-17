# dns-visualizer

DNS Visualizer - OpenPanel plugin to visualize DNS for a domain

![screenshot](https://i.postimg.cc/Qj3hzg18/slika.png)

Installation:
```bash
docker exec openpanel bash -c "pip install dnspython pyvis" && \
  cd /etc/openpanel/modules/ && git clone https://github.com/stefanpejcic/dns-visualizer && \
  docker restart openpanel
```

Update:
```bash
rm -rf /etc/openpanel/modules/dns-visualizer && \
  docker exec openpanel bash -c "pip install dnspython pyvis" && \
  cd /etc/openpanel/modules/ && git clone https://github.com/stefanpejcic/dns-visualizer && \
  docker restart openpanel
```

---

Documentation: https://openpanel.com/docs/articles/dev-experience/custom-plugins#example

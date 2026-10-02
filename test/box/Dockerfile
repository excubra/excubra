# A Debian 13 with systemd, the way a box finds it: what provision-box.sh is
# tried in before a release (see test/box/run.sh). Needs --privileged and the
# host's cgroup namespace, like every systemd in a container.
FROM debian:13
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus openssh-server iproute2 iputils-ping curl ca-certificates procps kmod \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-logind.service getty.target console-getty.service systemd-udevd.service 2>/dev/null || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

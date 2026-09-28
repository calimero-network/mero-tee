# GCE disk naming (vendored)

`65-gce-disk-naming.rules` and `google_nvme_id`, unmodified, from
[GoogleCloudPlatform/guest-configs](https://github.com/GoogleCloudPlatform/guest-configs)
at `67acac7d5af9d1e55a2e28254d325df3d119e2e5` (`src/lib/udev/`), Apache-2.0
(`LICENSE`).

They make udev link each attached disk as `/dev/disk/by-id/google-<deviceName>`,
which is how `calimero-init` finds the data disk mdma attaches as `data`. On a
stock GCE image they come from `google-compute-engine`, which also pulls in the
guest agent and OS Login. The locked-read-only image shipped neither file
(nodes logged `MISSING:` for both), so the link never appeared and nodes fell
back to picking the one unused disk. Vendoring the two files gives the naming
without the agents the image locks out.

`google_nvme_id` reads the device name from the NVMe namespace's vendor
extension with `nvme id-ns -b`, so the image installs `nvme-cli`.

**Installed last, in `playbook.yml`'s post_tasks, not by the merotee role.** The
base image's `google-compute-engine` package owns these same paths, and
merod-lockdown's `openssh-server` purge removes it along with its OS Login and
guest-agent dependants, so dpkg deleted anything the role had written there on
every locked-read-only build. The post_tasks then assert both, and the seal
checks them inside the EROFS image (`--require`).

To update: copy both files from a newer guest-configs commit and change the
commit above.

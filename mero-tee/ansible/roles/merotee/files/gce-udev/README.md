# GCE disk naming (vendored)

`65-gce-disk-naming.rules` and `google_nvme_id`, unmodified, from
[GoogleCloudPlatform/guest-configs](https://github.com/GoogleCloudPlatform/guest-configs)
at `67acac7d5af9d1e55a2e28254d325df3d119e2e5` (`src/lib/udev/`), Apache-2.0
(`LICENSE`).

They make udev link each attached disk as `/dev/disk/by-id/google-<deviceName>`,
which is how `calimero-init` finds the data disk mdma attaches as `data`. On a
stock GCE image they come from `google-compute-engine`, which also pulls in the
guest agent and OS Login. The image as built had neither file (2.3.86 nodes
logged `MISSING:` for both), so the link never appeared and nodes fell back to
picking the one unused disk. Vendoring the two files gives the naming
without the agents the image locks out.

`google_nvme_id` reads the device name from the NVMe namespace's vendor
extension with `nvme id-ns -b`, so the image installs `nvme-cli`.

To update: copy both files from a newer guest-configs commit and change the
commit above.

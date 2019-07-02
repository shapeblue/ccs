#!/bin/bash

RELEASE="v1.11.4"
start_dir="$PWD"
iso_dir="${start_dir}/iso"
working_dir="${iso_dir}/${RELEASE}"
mkdir -p "${working_dir}"

CNI_VERSION="v0.7.1"
echo "Downloading CNI ${CNI_VERSION}..."
cni_dir="${working_dir}/cni/${CNI_VERSION}"
mkdir -p "${cni_dir}"
curl -L "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-amd64-${CNI_VERSION}.tgz" | tar -C "${cni_dir}" -xz

CRICTL_VERSION="v1.11.1"
echo "Downloading CRI tools ${CRICTL_VERSION}..."
crictl_dir="${working_dir}/cri-tools/${CRICTL_VERSION}"
mkdir -p "${crictl_dir}"
curl -L "https://github.com/kubernetes-incubator/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz" | tar -C "${crictl_dir}" -xz

echo "Downloading Kubernetes tools ${RELEASE}..."
k8s_dir="${working_dir}/k8s"
mkdir -p "${k8s_dir}"
cd "${k8s_dir}"
curl -L --remote-name-all https://storage.googleapis.com/kubernetes-release/release/${RELEASE}/bin/linux/amd64/{kubeadm,kubelet,kubectl}
chmod +x {kubeadm,kubelet,kubectl}

echo "Downloading kubelet.service ${RELEASE}..."
cd $start_dir
kubelet_service_file="${working_dir}/kubelet.service"
touch "${kubelet_service_file}"
curl -sSL "https://raw.githubusercontent.com/kubernetes/kubernetes/${RELEASE}/build/debs/kubelet.service" | sed "s:/usr/bin:/opt/bin:g" > ${kubelet_service_file}
echo "Downloading 10-kubeadm.conf ${RELEASE}..."
kubeadm_conf_file="${working_dir}/10-kubeadm.conf"
touch "${kubeadm_conf_file}"
curl -sSL "https://raw.githubusercontent.com/kubernetes/kubernetes/${RELEASE}/build/debs/10-kubeadm.conf" | sed "s:/usr/bin:/opt/bin:g" > ${kubeadm_conf_file}

echo "Fetching k8s docker images..."
docker -v
if [ $? -ne 0 ]; then
    sudo apt update && sudo apt install docker.io -y
    sudo systemctl enable docker && sudo systemctl start docker
fi
mkdir -p "${working_dir}/docker"
output=`${k8s_dir}/kubeadm config images list`
while read -r line; do
    echo "Pulling docker image $line ---"
    sudo docker pull "$line"
    image_name=`echo "$line" | grep -oE "[^/]+$"`
    sudo docker save "$line" > "${working_dir}/docker/$image_name.tar"
done <<< "$output"

mkisofs -o setup.iso -J -R -l "${iso_dir}"

rm -rf "${iso_dir}"

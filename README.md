# Install Microk8s
## https://microk8s.io/docs
```
snap install microk8s --classic --channel=1.24/stable
```
## Add all cluster nodes to /etc/hosts

## kubectl and ctr CLI aliases
```
snap alias microk8s.kubectl kubectl
snap alias microk8s.kubectl k
snap alias microk8s.ctr ctr
```

## Enable Kubernetes Role Based Access Control
```
microk8s enable rbac
```

## Set custom DNS forwareders before enable CoreDNS
```
sed -i 's/$NAMESERVERS/1.1.1.1 8.8.8.8/g' \
  /var/snap/microk8s/common/addons/core/addons/dns/coredns.yaml
```
```
microk8s enable dns
```

## Enable Cluster Metrics
```
microk8s enable metrics-server
```

## Fix PodDisruptionBudget apiVersion
```
grep -B1 PodDisruptionBudget /var/snap/microk8s/current/args/cni-network/cni.yaml \
  | grep apiVersion
```
```
sed -i 's|apiVersion: policy/v1beta1|apiVersion: policy/v1|g' \
  /var/snap/microk8s/current/args/cni-network/cni.yaml
```
```
kubectl apply -f /var/snap/microk8s/current/args/cni-network/cni.yaml
```

## Optional: change Calico from VXLAN to BGP Mode
```
kubectl delete -f /var/snap/microk8s/current/args/cni-network/cni.yaml
```
```
microk8s stop && microk8s start
```
```
vi /var/snap/microk8s/current/args/cni-network/cni.yaml
# change  calico_backend => bird
# change  CALICO_IPV4POOL_IPIP => CrossSubnet
# comment CALICO_IPV4POOL_VXLAN
# add     FELIX_USAGEREPORTINGENABLED => false
```
```
kubectl apply -f /var/snap/microk8s/current/args/cni-network/cni.yaml
```

# Test Deployment and Expose as Service NodePort
```
kubectl create deployment httpd --image=httpd --port=80
```
```
kubectl get pods -o wide
```
```
kubectl expose deployment httpd --type=NodePort --port=80 --name=httpd \
  --dry-run=client -o yaml > httpd.yaml
```
```
kubectl apply -f httpd.yaml
```

## Connect to the httpd service using the node port
```
NODE_PORT=$(kubectl describe service httpd | grep ^NodePort | grep -Eo '[0-9]*')
NODE_IP=$(ip route get 1 | awk '{print $7;exit}')
NODE_IP=$(kubectl get pod -l app=httpd -o jsonpath='{.items[0].status.hostIP}')

curl -fsSL $NODE_IP:$NODE_PORT
curl -fsSL localhost:$NODE_PORT
```

## Test Scaling the Deployment
```
kubectl scale deployment httpd --replicas=3
```

# Ingress Controller
## Optional: Ingress Cert
```
openssl req -x509 -nodes -days 3650 -new -subj "/CN=test.wiltoncarvalho.com" \
  -newkey rsa:2048 -keyout key.pem -out cert.pem
```
```
kubectl create secret tls test-secret \
  --key key.pem --cert cert.pem --namespace default
```

## Enable Microk8s default Ingress
```
# microk8s.enable ingress:default-ssl-certificate=namespace/secretname
microk8s enable ingress
```

## Set the default ingress backend to the httpd service
```
cat <<EOF> test-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
spec:
  ingressClassName: public
  defaultBackend:
    service:
      name: httpd
      port:
        number: 80
EOF
```
```
kubectl apply -f test-ingress.yaml
```

## Connect to the httpd service using the ingress
```
curl localhost
```

# Enable Cluster Dashboard
```
microk8s enable dashboard
```

## The Admin Token can be used to access the Dashboard
```
microk8s config | grep token
```

## Or use microk8s.dashboard-proxy to setup dashboard login
```
microk8s.dashboard-proxy
CTRL+C
```

## Dashboard Ingress
```
cat <<EOF> dashboard-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
  name: dashboard
  namespace: kube-system
spec:
  ingressClassName: public
  tls:
  - hosts:
    - "dashboard.example.com"
  rules:
  - host: "dashboard.example.com"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes-dashboard
            port:
              number: 443
EOF
```
```
kubectl apply -f dashboard-ingress.yaml
```

## Connect to the Dashboard service using the ingress
```
curl --resolve dashboard.example.com:443:127.0.0.1 -fsSL -k https://dashboard.example.com \
  | grep -o '<title>Kubernetes Dashboard</title>'
```

```
NODE_IP=$(ip route get 1 | awk '{print $7;exit}')
NODE_IP=$(kubectl -n ingress get pod -l name=nginx-ingress-microk8s -o jsonpath='{.items[0].status.hostIP}')
```
```
curl --resolve dashboard.example.com:443:$NODE_IP -fsSL -k https://dashboard.example.com \
  | grep -o '<title>Kubernetes Dashboard</title>'
```
# Add Nodes to the Cluster
## Add all cluster nodes to /etc/hosts
```
microk8s add-node
```
# Install Helm
```
microk8s enable helm3

snap alias microk8s.helm3 helm

helm version
```

# Troubleshooting
## Using cri-tools (crtctl) to manage containers
```
curl -fsSL https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.24.2/crictl-v1.24.2-linux-amd64.tar.gz \
  | sudo tar zxvf - -C "/usr/local/bin"
```
```
crictl --version
```
```
export CONTAINER_RUNTIME_ENDPOINT=unix:///var/snap/microk8s/common/run/containerd.sock
```
```
crictl pods
crictl ps -a | grep httpd
crictl logs --tail=10 fa1245f834da5
crictl exec -it fa1245f834da5 bash
```
## Using containerd cli (ctr) to manage containers
```
ContainerIDs=$(kubectl describe pod httpd | grep 'Container ID' | awk -F '/' '{print $NF}')
```
```
ContainerID=$(for i in $ContainerIDs; do ctr task ls | grep -o $i | tail -1; done)
```
```
ctr task exec --exec-id 9999 --user 0:0 --tty $ContainerID bash
```
# Maintenance
## Before Microk8s Node Maintenance
```
# DRAIN THE PODS
kubectl drain node-3 --ignore-daemonsets --delete-emptydir-data --force

# CHECK THE PODS
kubectl get pods -A
kubectl get nodes -o wide
```

## After Microk8s Node Maintenance
```
kubectl uncordon node-3
```

## Microk8s Remove Node from the Cluster
## To remove the node node-3
## Run on the node-3
```
microk8s leave
```
## On another node(node-1 or node-2 or node-x)
```
microk8s remove-node node-3
```


# NFS Server
```
sudo apt-get install nfs-kernel-server
```

## Create a directory to be used for NFS and create an anonymous user
```
sudo mkdir -p /srv/nfs
sudo groupadd --gid 60001 anongid
sudo useradd -s /usr/sbin/nologin -d /nonexistent -g anongid --uid 60001 anonuid
sudo chown anonuid:anongid /srv/nfs
sudo chmod 0775 /srv/nfs
```

## Add the directory to the exports file
```
sudo mv /etc/exports /etc/exports.bak
echo '/srv/nfs 192.168.122.0/24(rw,sync,no_subtree_check,root_squash,anonuid=60001,anongid=60001)' | sudo tee /etc/exports
```
```
sudo systemctl restart nfs-kernel-server
```

## Test NFS Client on a client node
```
sudo apt install nfs-common
```
```
sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2 NFS_SERVER:/srv/nfs /mnt
sudo umount /mnt
```

## Test using the /etc/fstab
```
NFS_SERVER:/srv/nfs-k8s /mnt nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noauto,_netdev 0 0
sudo mount /mnt
sudo umount /mnt
```

# NFS CSI Driver
```
helm repo add csi-driver-nfs \
  https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/charts
```
```
helm repo update
```
```
helm install csi-driver-nfs csi-driver-nfs/csi-driver-nfs \
  --namespace kube-system \
  --set kubeletDir=/var/snap/microk8s/common/var/lib/kubelet \
  --set driver.mountPermissions=0775
```
```
kubectl get csidrivers
```

## Storage Class - sc-nfs.yaml
```
cat <<EOF> sc-nfs.yaml
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-csi
provisioner: nfs.csi.k8s.io
parameters:
  server: 192.168.122.96
  share: /srv/nfs
reclaimPolicy: Retain
volumeBindingMode: Immediate
mountOptions:
  - hard
  - nfsvers=4.1
EOF
```
```
kubectl apply -f sc-nfs.yaml
kubectl describe sc nfs-csi
```

## Persistent Volume Claim - pvc-nfs.yaml
```
cat <<EOF> pvc-nfs.yaml
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-pvc
spec:
  storageClassName: nfs-csi
  accessModes: [ReadWriteMany]
  resources:
    requests:
      storage: 4Gi
EOF
```
```
kubectl apply -f pvc-nfs.yaml
kubectl describe pvc my-pvc
```

## Persistent Volume - my-pod.yaml
```
cat <<EOF> my-pod.yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: my-pod
    image: nginx:stable
    ports:
    - containerPort: 80
      name: http
    volumeMounts:
    - mountPath: /usr/share/nginx/html
      name: my-pod-data
  volumes:
  - name: my-pod-data
    persistentVolumeClaim:
      claimName: my-pvc
EOF
```
```
kubectl apply -f my-pod.yaml
```
```
kubectl exec my-pod -- df -h /usr/share/nginx/html
kubectl exec my-pod -- sh -c 'echo ok > /usr/share/nginx/html/index.html'
```
```
POD_IP=$(kubectl get pod my-pod -o wide -o jsonpath='{.status.podIP}')
curl -fsSL $POD_IP
kubectl logs pod/my-pod
```

## Persistent Volume - alpine.yaml
```
cat <<'EOF'> alpine.yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: alpine
  name: alpine
spec:
  replicas: 3
  selector:
    matchLabels:
      app: alpine
  template:
    metadata:
      labels:
        app: alpine
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 0
        fsGroup: 1000
      volumes:
      - name: alpine-vol
        persistentVolumeClaim:
          claimName: my-pvc
      containers:
      - name: alpine
        image: python:3-alpine
        workingDir: /mnt
        command:
        - sh
        - -c
        - |
          ln -sf /proc/self/fd/1 /tmp/stdout.log
          > /tmp/stdout.log 2>&1
          python3 -m http.server 8080 &
          pid="$!"
          echo "[ Started PID $pid ]"
          trap "echo '[ Stopping PID $pid ]' && kill -TERM $pid && sleep 3" INT TERM WINCH QUIT
          wait $pid
          return_code="$?"
          exit $return_code
        volumeMounts:
        - name: alpine-vol
          mountPath: /mnt
        securityContext:
          allowPrivilegeEscalation: false
        resources:
          requests:
            cpu: 128m
            memory: 32Mi
          limits:
            cpu: 128m
            memory: 32Mi
EOF
```
```
kubectl apply -f alpine.yaml
```
```
kubectl exec alpine -- df -h /mnt

kubectl exec alpine -- sh -c 'echo test > /mnt/test.txt'

kubectl exec alpine -- ls -lh /mnt

POD_IP0=$(kubectl get pod -l app=alpine -o jsonpath='{.items[0].status.podIP}')
POD_IP1=$(kubectl get pod -l app=alpine -o jsonpath='{.items[1].status.podIP}')
POD_IP2=$(kubectl get pod -l app=alpine -o jsonpath='{.items[2].status.podIP}')

curl -fsSL $POD_IP0:8080/test.txt
curl -fsSL $POD_IP1:8080/test.txt
curl -fsSL $POD_IP2:8080/test.txt

kubectl logs -l app=alpine
```

# Backup and Restore
```
microk8s dbctl backup [-o backup-file]
microk8s dbctl restore <backup-file.tar.gz>
```

# Cert Manager DNS Validated LE Wildcard Cert
```
#kubectl create secret generic le-secret --namespace default
openssl req -x509 -nodes -days 3650 -new -subj "/CN=wiltoncarvalho.com" \
  -addext "subjectAltName=DNS:wiltoncarvalho.com,DNS:*.wiltoncarvalho.com" \
  -newkey rsa:2048 -keyout key.pem -out cert.pem
```
```
kubectl create secret tls le-secret \
  --key key.pem --cert cert.pem --namespace default
```
```
cat <<EOF> wildcard-cert-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dummy-load-certificates
  namespace: default
spec:
  tls:
  - hosts:
    - "*.wiltoncarvalho.com"
    secretName: le-secret
  rules:
  - host: "*.wiltoncarvalho.com"
EOF
```
```
kubectl apply -f wildcard-cert-ingress.yaml
```

## Install the Cert Manager Controller using Helm
```
helm repo add jetstack https://charts.jetstack.io
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.8.0 \
  --set installCRDs=true
```

## DNS CA API Key
```
cat <<EOF> certs.yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-api-token
type: Opaque
stringData:
  api-token: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: letsencrypt-staging
  namespace: default
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory 
    privateKeySecretRef:
      name: letsencrypt
    solvers:
    - dns01:
        cloudflare:
          email: wiltonweb@gmail.com
          apiTokenSecretRef:
            name: cloudflare-api-token
            key: api-token

---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wiltoncarvalho-com
  namespace: default
spec:
  secretName: tls-secret
  issuerRef:
    kind: Issuer
    name: letsencrypt
  commonName: wiltoncarvalho.com
  dnsNames:
  - "wiltoncarvalho.com"
  - "*.wiltoncarvalho.com"
EOF
```
```
kubectl apply -f certs.yaml
```
```
kubectl describe certificate wiltoncarvalho-com
```

## HTTPS APP
```
kubectl apply -f app.yaml
```

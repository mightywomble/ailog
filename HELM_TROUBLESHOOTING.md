# Helm Deployment Troubleshooting & Best Practices

## ⚠️ Common Issues & Solutions

### Issue: Deployment Hangs or Times Out

**Symptoms:**
- `helm upgrade --install` command appears to hang indefinitely
- Pods remain in `Pending` or `ContainerCreating` state
- Readiness probes continuously fail

**Root Causes:**
1. **KUBECONFIG not set** – Helm cannot communicate with the cluster
2. **Slow application startup** – Flask app takes too long to become ready
3. **Pod scheduling issues** – Insufficient resources or node constraints
4. **Persistent volume problems** – PVC not binding or mounting

**Solutions:**

#### 1. Verify KUBECONFIG is Set
```bash
# BEFORE running any helm commands, export KUBECONFIG
export KUBECONFIG=~/.kube/config

# Verify connectivity
kubectl config current-context
kubectl cluster-info

# Test API access
kubectl get nodes
```

**IMPORTANT:** If `KUBECONFIG` is not set, `helm` will silently fail or hang trying to reach the cluster.

#### 2. Increase Startup Timeout
The Helm deployment includes startup probes that allow up to 5 minutes (30 attempts × 10 seconds) for the app to become ready:

```yaml
# These are configured in helm/values.yaml
startupProbe:
  httpGet:
    path: /
    port: http
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 30  # 5 minutes total
```

If your deployment is still timing out, increase the failure threshold:
```bash
helm upgrade --install ailog ./helm -n ailog \
  --set startupProbeFailureThreshold=60  # 10 minutes total
```

#### 3. Monitor Rollout Progress
Instead of waiting indefinitely, actively watch the deployment:
```bash
# In a separate terminal
kubectl -n ailog get pods -w

# In another terminal, check pod logs
kubectl -n ailog logs -f deploy/ailog

# Check events in the namespace
kubectl -n ailog get events --sort-by='.lastTimestamp'
```

#### 4. Check Persistent Volume Claims
If using persistence, verify the PVC is binding:
```bash
# List PVCs in the namespace
kubectl -n ailog get pvc

# Check PVC status
kubectl -n ailog describe pvc ailog

# If stuck in Pending, check available storage classes
kubectl get sc

# Verify the storage class exists in values.yaml
grep storageClass helm/values.yaml
```

---

### Issue: Pod Crashes Immediately (ImagePullBackOff)

**Symptoms:**
- `kubectl get pods` shows `ImagePullBackOff` status
- Pod logs: "Failed to pull image"

**Solutions:**

#### 1. Verify Image Exists and Is Accessible
```bash
# Check if image is built and tagged
docker images | grep ailog

# Verify push succeeded
docker push mightywomble/ailog:latest

# Test image pull from cluster node
docker pull mightywomble/ailog:latest
```

#### 2. Update Image Tag in Deployment
```bash
# Deploy with correct image
helm upgrade --install ailog ./helm -n ailog \
  --set image.repository=mightywomble/ailog \
  --set image.tag=latest \
  --set image.pullPolicy=Always
```

---

### Issue: Port Already in Use (Service Port Conflict)

**Symptoms:**
- Deployment succeeds but service doesn't bind
- `kubectl describe svc ailog` shows LoadBalancer pending

**Solution:**
```bash
# Change the service port
helm upgrade --install ailog ./helm -n ailog \
  --set service.port=5002  # Use different port if 5001 is in use
```

---

### Issue: PVC Multi-Attach Error During Rollout

**Symptoms:**
- Old pod won't terminate
- New pod can't mount PVC: "Multi-Attach error: volume ... is already attached"

**Solution:**
```bash
# Force pod termination by scaling to 0
kubectl -n ailog scale deploy/ailog --replicas=0

# Wait for old pod to be fully terminated
sleep 10
kubectl -n ailog get pods

# Scale back to 1 replica
kubectl -n ailog scale deploy/ailog --replicas=1

# Watch the new deployment
kubectl -n ailog rollout status deploy/ailog
```

---

## 🔍 Debugging Commands

### Check Deployment Status
```bash
# Overall status
kubectl -n ailog get deploy ailog

# Detailed description
kubectl -n ailog describe deploy ailog

# Recent events
kubectl -n ailog get events --sort-by='.lastTimestamp' | head -20
```

### View Pod Logs
```bash
# Last 100 lines from current pod
kubectl -n ailog logs --tail=100 deploy/ailog

# Follow logs in real-time
kubectl -n ailog logs -f deploy/ailog

# Logs from previously crashed container
kubectl -n ailog logs --previous deploy/ailog
```

### Check Pod Details
```bash
# List all pods in namespace
kubectl -n ailog get pods -o wide

# Detailed pod information
kubectl -n ailog describe pod <pod-name>

# Pod resource usage
kubectl -n ailog top pods
```

### Check Service Connectivity
```bash
# Port forward for local access
kubectl -n ailog port-forward svc/ailog 5001:5001

# In another terminal
curl http://localhost:5001
```

---

## ✅ Verification Checklist

After deployment, verify everything is working:

```bash
# 1. Check deployment is running
kubectl -n ailog get deploy
# Expected: ailog READY 1/1

# 2. Check pod is healthy
kubectl -n ailog get pods
# Expected: ailog-xxx Running 1/1

# 3. Check service is ready
kubectl -n ailog get svc
# Expected: ailog ClusterIP ... port 5001

# 4. Check PVC is bound (if enabled)
kubectl -n ailog get pvc
# Expected: ailog Bound pvc-xxx

# 5. Access the application
kubectl -n ailog port-forward svc/ailog 5001:5001
# Then open http://localhost:5001 in browser

# 6. Check logs for errors
kubectl -n ailog logs deploy/ailog | grep -i error
```

---

## 🚀 Best Practices

### 1. Always Set KUBECONFIG Before Helm Commands
```bash
# Create a shell function for convenience
export KUBECONFIG=~/.kube/config
```

Or add to your shell profile (`.bashrc`, `.fish`, etc.):
```bash
# ~/.bashrc or ~/.fish (add to config.fish for fish shell)
export KUBECONFIG=~/.kube/config
```

### 2. Use Namespace Isolation
Always deploy to a specific namespace to avoid conflicts:
```bash
helm upgrade --install ailog ./helm -n ailog --create-namespace
```

### 3. Use Values Files for Complex Configurations
Instead of long `--set` commands, use a values file:
```bash
# Create custom-values.yaml
cat > custom-values.yaml <<EOF
image:
  repository: mightywomble/ailog
  tag: v1.0.0
tailscale:
  enabled: true
  hostname: ailog-prod
persistence:
  enabled: true
  size: 10Gi
EOF

# Deploy with custom values
helm upgrade --install ailog ./helm -n ailog -f custom-values.yaml
```

### 4. Use Dry-Run Before Deploying
```bash
# Validate the Helm chart and see what will be created
helm upgrade --install ailog ./helm -n ailog --dry-run --debug

# Actually deploy only when dry-run looks good
helm upgrade --install ailog ./helm -n ailog
```

### 5. Monitor Rollouts
```bash
# Watch rollout in real-time
kubectl -n ailog rollout status deploy/ailog --timeout=5m

# If it times out, check what went wrong
kubectl -n ailog describe deploy ailog
kubectl -n ailog logs deploy/ailog
```

### 6. Clean Rollout Strategy for Updates
```bash
# For safe updates without downtime (if replicas > 1):
kubectl -n ailog set image deploy/ailog ailog=mightywomble/ailog:new-tag

# Or use Helm upgrade with watch:
helm upgrade ailog ./helm -n ailog --set image.tag=new-tag
kubectl -n ailog rollout status deploy/ailog --timeout=5m
```

---

## 📝 Pre-Deployment Checklist

Before running `helm upgrade --install`:

- [ ] KUBECONFIG environment variable is set: `echo $KUBECONFIG`
- [ ] Correct cluster context: `kubectl config current-context`
- [ ] Docker image is built and pushed: `docker push mightywomble/ailog:<tag>`
- [ ] Target namespace exists or will be created: `kubectl get ns <namespace>`
- [ ] Storage class available (if persistence enabled): `kubectl get sc`
- [ ] Sufficient cluster resources: `kubectl top nodes`
- [ ] No existing AILog deployment or plan to upgrade: `kubectl get deploy -A | grep ailog`
- [ ] Review values in `helm/values.yaml` or custom values file
- [ ] Run dry-run: `helm upgrade --install ailog ./helm -n ailog --dry-run`

---

## 🔧 Recovery Procedures

### If Deployment Gets Stuck

```bash
# 1. Stop the current rollout
kubectl -n ailog rollout undo deploy/ailog

# 2. Scale down to zero
kubectl -n ailog scale deploy/ailog --replicas=0

# 3. Wait a moment
sleep 10

# 4. Check resources are freed
kubectl -n ailog get pods
kubectl -n ailog get pvc

# 5. Try again with debug information
helm upgrade --install ailog ./helm -n ailog --debug
kubectl -n ailog get events -w  # Watch events in another terminal
```

### Complete Clean Removal

If you need to completely remove and redeploy:

```bash
# 1. Uninstall the Helm release
helm uninstall ailog -n ailog

# 2. Delete the namespace (careful - this deletes everything)
kubectl delete ns ailog

# 3. Wait for namespace to terminate
kubectl get ns ailog --watch

# 4. Redeploy fresh
helm upgrade --install ailog ./helm -n ailog --create-namespace
```

---

## 📚 Additional Resources

- [Kubernetes Official Docs: Troubleshooting Deployments](https://kubernetes.io/docs/tasks/run-application/run-stateless-application-deployment/#updating-the-deployment)
- [Helm Documentation](https://helm.sh/docs/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

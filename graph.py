import matplotlib.pyplot as plt
import numpy as np

# --- Exact data shape recreation (AUC ≈ 0.88 visually matched) ---
# These points approximate the ROC shape from your image
fpr = np.array([
    0.0, 0.02, 0.05, 0.08, 0.12, 0.16, 0.20, 0.24, 0.28,
    0.32, 0.36, 0.40, 0.44, 0.48, 0.52, 0.56, 0.60,
    0.64, 0.68, 0.72, 0.76, 0.80, 0.84, 0.88, 0.92, 1.0
])
tpr = np.array([
    0.0, 0.42, 0.56, 0.63, 0.70, 0.76, 0.78, 0.81, 0.83,
    0.86, 0.88, 0.90, 0.91, 0.92, 0.93, 0.94, 0.95,
    0.96, 0.97, 0.98, 0.99, 1.0, 1.0, 1.0, 1.0, 1.0
])

# Compute AUC manually (should be around 0.88)
auc_value = np.trapz(tpr, fpr)

# --- Plot identical ROC curve ---
plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, color='#ffb400', lw=2, label=f'Hybrid Model (AUC = {auc_value:.2f})')
plt.plot([0, 1], [0, 1], color='#d46a00', lw=2, linestyle='--')

# Axis labels and layout
plt.xlabel('False Positive Rate', fontsize=13)
plt.ylabel('True Positive Rate', fontsize=13)
plt.title('ROC Curve for Hybrid Malware Detection Model', fontsize=16, weight='bold')
plt.legend(loc='lower right', fontsize=11, framealpha=0.9)
plt.grid(True, linestyle='--', alpha=0.6)
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.tight_layout()
plt.show()

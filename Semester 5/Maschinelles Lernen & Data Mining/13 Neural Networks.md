**Problem**
Traditional machine learning models like **decision trees**, **logistic regression**, and **SVMs** often struggle to handle **complex patterns** and **high-dimensional data**.

**Solution**
Neural networks (NNs) are **flexible models** capable of learning **complex, non-linear relationships** without manual feature engineering.
# Node & (Hidden) Layers
![[The StatQuest Illustrated Guide to Machine Learning 32.jpeg|800]]

![[The StatQuest Illustrated Guide to Machine Learning 33.jpeg|800]]
# Activation Functions
![[The StatQuest Illustrated Guide to Machine Learning 30 1.jpeg|800]]

![[The StatQuest Illustrated Guide to Machine Learning 31.jpeg|800]]
## Rectified Linear Unit (ReLU)
![[The StatQuest Illustrated Guide to Machine Learning 27.jpeg|400]]
## SoftPlus
![[The StatQuest Illustrated Guide to Machine Learning 28.jpeg|400]]
## Sigmoid
![[The StatQuest Illustrated Guide to Machine Learning 29.jpeg|400]]
# Parameters
## Weights
![[The StatQuest Illustrated Guide to Machine Learning 23.jpeg|800]]
## Biases
![[The StatQuest Illustrated Guide to Machine Learning 24.jpeg|800]]
## Final Bias
![[The StatQuest Illustrated Guide to Machine Learning 25.jpeg|800]]
# Backpropagation
![[The StatQuest Illustrated Guide to Machine Learning 18.jpeg|800]]

![[The StatQuest Illustrated Guide to Machine Learning 19.jpeg|800]]

![[The StatQuest Illustrated Guide to Machine Learning 20.jpeg|800]]

![[The StatQuest Illustrated Guide to Machine Learning 21.jpeg|800]]
# Softmax & Multiclass Classification
The **Softmax function** generalizes logistic regression to multiclass classification by computing probabilities for each class:

$\text{softmax}(z_k) = \frac{e^{z_k}}{\sum_{j=1}^{K} e^{z_j}}$

- Computes a **probability distribution** across all classes.
- The class with the **highest probability** is selected as the prediction.
# Loss Functions
**Binary Classification:**
Use the **logistic loss function**: $L_{\text{logistic}} = -y \log(\hat{y}) - (1 - y) \log(1 - \hat{y})$

**Multiclass Classification (Softmax):**
Use the **cross-entropy loss**: $L_{\text{cross-entropy}} = -\sum_{k=1}^{K} y_k \log(\hat{y}_k)$
# Training Neural Networks
Training a neural network involves **adjusting the weights** to minimize the **loss function**.

**Steps:**
1. **Initialize weights randomly.**
2. **Compute the gradient of the cost function.**
3. **Update the weights using Gradient Descent:** $w{\prime} = w - \alpha \frac{\partial L}{\partial w}$

**Gradient Descent Variants:**
- **Mini-Batch Gradient Descent**: Uses a small batch of samples to update weights.
- **Backpropagation**: Efficiently computes gradients using the **chain rule**.
# Vanishing & Exploding Gradients
- **Vanishing Gradient Problem**: Gradients become very small, slowing down learning.
- **Exploding Gradient Problem**: Gradients become very large, leading to instability.

Solutions:
- Use **ReLU** activation functions.
- Use **batch normalization**.
# Dealing with Overfitting
**Techniques to Prevent Overfitting:**
1. **Dropout**:
	- Randomly drops neurons during training to prevent over-reliance on specific neurons.
	- Typical dropout rate: **20-50%**.
2. **Early Stopping**:
	- Stop training when the validation performance starts to degrade.
3. **Data Augmentation**:
	 - Apply transformations (scaling, cropping, flipping) to the training data to increase its size and diversity.
# Hyperparameters
Key **hyperparameters** that affect a neural network’s performance:
- **Number of layers**
- **Number of neurons per layer**
- **Activation functions**
- **Learning rate**
- **Batch size**
- **Number of epochs**
# Architectures of Neural Networks
- **Vanilla Feed-Forward Neural Networks**: Basic architecture where data flows forward through layers.
- **Convolutional Neural Networks (CNNs)**: Specialized for image data.
- **Recurrent Neural Networks (RNNs)**: Specialized for sequential data.
- **Transformers**: State-of-the-art architecture for NLP and other tasks.
- Measure performance
- Hyperlane
- Backpropagation (with Derivatives)
- PDF mit allen Präsentation
- PDF von StatQuest
- PDF Skript
- PDF mit allen Quizzes

# Logistic Regression
## Example 1
![[Pasted image 20250112201433.png|1000]]

**Given:**
- $\theta_0 = 13$
- $\theta_1 = -0.0004$
- Kilometerstand = 35,000 km

The goal is to calculate the **probability** that the car will be sold using the logistic regression formula.

___

**Step 1: Logistic Regression Formula**
The logistic regression formula is: $p(y=1|x) = \frac{1}{1 + e^{-z}}$

Where: $z = \theta_0 + \theta_1 \cdot x$

---

**Step 2: Calculate** $z$
Substitute the given values: $z = 13 + (-0.0004 \cdot 35000)$

First, calculate the term inside the multiplication: $-0.0004 \times 35000 = -14$

Now: $z = 13 - 14 = -1$

___

**Step 3: Apply the Logistic Function**
The logistic function is: $p(y=1|x) = \frac{1}{1 + e^{-(-1)}} = \frac{1}{1 + e^{1}}$

Approximating $e^1 \approx 2.718$: $p(y=1|x) = \frac{1}{1 + 2.718} \approx 0.269$

Thus, the probability is **26.9%**.
## Example 2
![[Pasted image 20250112201857.png|1000]]

**Given:**
- $\theta_0 = 14$
- $\theta_1 = -0.00035$
- $\theta_2 = -1.2$
- Kilometerstand = 35,000 km
- Age = 2 years

The goal is to calculate the **probability** that the car will be sold using both **kilometerstand** and **age**.

___

**Step 1: Extended Logistic Regression Formula**
Now, the logistic regression model includes two input features: kilometerstand and age.

$z = \theta_0 + \theta_1 \cdot \text{km} + \theta_2 \cdot \text{age}$

___

**Step 2: Calculate** $z$
Substitute the given values: $z = 14 + (-0.00035 \cdot 35000) + (-1.2 \cdot 2)$

First, calculate each term:
$-0.00035 \times 35000 = -12.25$
$-1.2 \times 2 = -2.4$

Now sum them up: $z = 14 - 12.25 - 2.4 = -0.65$

___

**Step 3: Apply the Logistic Function**
The logistic function is: $p(y=1|x) = \frac{1}{1 + e^{-(-0.65)}} = \frac{1}{1 + e^{0.65}}$

Approximating $e^{0.65} \approx 1.917$: $p(y=1|x) = \frac{1}{1 + 1.917} \approx 0.343$

Thus, the probability is **34.3%**.
# Quality Measures for Classification
## Example 1
![[Pasted image 20250112202243.png|1000]]

**1. Precision for Positive Class**
The formula for **Precision** is: $\text{Precision}_{\text{Positive}} = \frac{\text{True Positive (TP)}}{\text{True Positive (TP)} + \text{False Positive (FP)}}$

From the confusion matrix:
- **True Positive (TP)** = 30 (correctly predicted as positive)
- **False Positive (FP)** = 20 (incorrectly predicted as positive from other classes)

Now: $\text{Precision}_{\text{Positive}} = \frac{30}{30 + 20} = \frac{30}{50} = 0.6$

___

**2. Recall for Positive Class**
The formula for **Recall** is: $\text{Recall}_{\text{Positive}} = \frac{\text{True Positive (TP)}}{\text{True Positive (TP)} + \text{False Negative (FN)}}$

From the confusion matrix:
- **True Positive (TP)** = 30
- **False Negative (FN)** = 10 (actual positives that were incorrectly predicted as negative)

Now: $\text{Recall}_{\text{Positive}} = \frac{30}{30 + 10} = \frac{30}{40} = 0.75$

___

**3. F1-Score for Positive Class**
The formula for **F1-Score** is: $F1_{\text{Positive}} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$

Substitute the values: $F1_{\text{Positive}} = 2 \times \frac{0.6 \times 0.75}{0.6 + 0.75}$

First, calculate the numerator and denominator: $F1_{\text{Positive}} = 2 \times \frac{0.45}{1.35}$

Now: $F1_{\text{Positive}} = 2 \times 0.333 = 0.666$
## Example 2
![[Pasted image 20250112203246.png|1000]]

**Step 1: Confusion Matrix for Negative Class (Non-Spam)**

|                    | **Actual Non-Spam (Negative)** | **Actual Spam (Positive)** |
|--------------------|---------------------------------|----------------------------|
| **Predicted Non-Spam (Negative)** | 78                              | 2                          |
| **Predicted Spam (Positive)**     | 7                               | 13                         |

___

**Step 2: Calculating Precision for the Negative Class**
The formula for **Precision** is: $\text{Precision}_{\text{Negative}} = \frac{\text{True Negatives (TN)}}{\text{True Negatives (TN)} + \text{False Positives (FP)}}$

From the confusion matrix:
- **True Negatives (TN)** = 78
- **False Positives (FP)** = 7

Substitute the values: $\text{Precision}_{\text{Negative}} = \frac{78}{78 + 7} = \frac{78}{85} \approx 0.9176$

___

**Step 3: Calculating Recall for the Negative Class**
The formula for **Recall** is: $\text{Recall}_{\text{Negative}} = \frac{\text{True Negatives (TN)}}{\text{True Negatives (TN)} + \text{False Negatives (FN)}}$

From the confusion matrix:
- **True Negatives (TN)** = 78
- **False Negatives (FN)** = 2

Substitute the values: $\text{Recall}_{\text{Negative}} = \frac{78}{78 + 2} = \frac{78}{80} = 0.975$

___

**Step 4: Calculating F1-Score for the Negative Class**
The formula for **F1-Score** is: $F1_{\text{Negative}} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$

Substitute the values: $F1_{\text{Negative}} = 2 \times \frac{0.9176 \times 0.975}{0.9176 + 0.975}$

First, calculate the numerator and denominator: $F1_{\text{Negative}} = 2 \times \frac{0.8942}{1.8926}$

Now: $F1_{\text{Negative}} \approx 0.945$

# Learning Curves
## Example 1
![[Pasted image 20250112211938.png|1000]]
# Gradient Descent
## Example 1
![[Pasted image 20250112204314.png|1000]]

You are given:
- $w = 1$ (initial weight)
- Gradient: $g = \frac{dL}{dw} = -0.5$
- Step size (learning rate): $\alpha = 0.1$

The goal is to calculate the **new weight** $w{\prime}$ after one step of Gradient Descent.

___

**Formula for Gradient Descent:**
The update rule for Gradient Descent is: $w{\prime} = w - \alpha \cdot g$

Where:
- $w$ = current weigh
- $\alpha$ = step size (learning rate)
- $g$ = gradient of the loss function with respect to $w$

___

**Step 1: Substitute the values**
$w{\prime} = 1 - 0.1 \cdot (-0.5)$

**Step 2: Simplify the equation**
$w{\prime} = 1 + 0.05$

**Step 3: Final result**
$w{\prime} = 1.05$
# Neural Networks
## Activation Function
![[Pasted image 20250112210106.png|1000]]

**Step 1: Calculate** $u_1$ **(First Hidden Node)**
The formula to calculate the input to any node in a neural network is: $u = \sum_{i=1}^{n} w_i \cdot x_i + b$

For $u_1$, based on the diagram, the connections are:
- $x_1$ with weight $w_1 = 1$
- $x_2$ with weight $w_2 = -1$
- Bias with weight $w_b = -1$

Thus, the formula for $u_1$ becomes: $u_1 = (w_1 \cdot x_1) + (w_2 \cdot x_2) + (w_b \cdot 1)$

Substitute the weights: $u_1 = (1 \cdot x_1) + (-1 \cdot x_2) + (-1 \cdot 1)$

Now substitute $x_1 = -1$ and $x_2 = -1$: $u_1 = (1 \cdot -1) + (-1 \cdot -1) + (-1 \cdot 1)$

Simplify: $u_1 = -1 + 1 - 1 = -1$

Now apply the **sign activation function**: $sgn(u_1) = sgn(-1) = -1$

Thus, the output of $u_1$ is **-1**.

___

**Step 2: Calculate** $u_2$ **(Second Hidden Node)**
For $u_2$, the connections are:
- $x_1$ with weight $w_1 = -1$
- $x_2$ with weight $w_2 = 1$
- Bias with weight $w_b = -1$

Using the same formula: $u_2 = (w_1 \cdot x_1) + (w_2 \cdot x_2) + (w_b \cdot 1)$

Substitute the weights: $u_2 = (-1 \cdot x_1) + (1 \cdot x_2) + (-1 \cdot 1)$

Now, substitute $x_1 = -1$ and $x_2 = -1$: $u_2 = (-1 \cdot -1) + (1 \cdot -1) + (-1 \cdot 1)$

Simplify: $u_2 = 1 - 1 - 1 = -1$

Now apply the **sign activation function**: $sgn(u_2) = sgn(-1) = -1$

This, the output of $u_2$ is **-1**.

___

**Step 3: Calculate** $Y$ **(Output Node)**
The output node $Y$ takes inputs from $u_1$, $u_2$, and a bias term $b$.

The formula for the output node is: $Y = (w_1 \cdot u_1) + (w_2 \cdot u_2) + (w_b \cdot 1)$

From the diagram:
- $u_1$ with weight $w_1 = 1$
- $u_2$ with weight $w_2 = 1$
- Bias with weight $w_b = -1$

Substitute the values: $Y = (1 \cdot u_1) + (1 \cdot u_2) + (-1 \cdot 1)$

Substitute $u_1 = -1$ and $u_2 = -1$: $Y = (1 \cdot -1) + (1 \cdot -1) + (-1 \cdot 1)$

Simplify: $Y = -1 - 1 - 1 = -3$

Apply the **sign activation function**: $sgn(Y) = sgn(-3) = -1$

**Final Output:** $Y = -1$
## Backprop
![[Pasted image 20250112204942.png|1000]]

**Neural Network Structure Recap:**
1. **Input node:** $x$
2. **First hidden layer:** $u_1$ and $u_2$
3. **Second hidden layer:** $v_1$ and $v_2$
4. **Output node:** $f$

The weight $w$ connects $x$ to both $u_1$ and $u_2$.

___

**Step 1: Breakdown of the Chain Rule**
We need to follow all possible paths from $w$ to $f$ and apply the chain rule to each path.

There are **two paths** from $w$ to $f$:
1. $w \rightarrow u_1 \rightarrow v_1 \rightarrow f$
2. $w \rightarrow u_1 \rightarrow v_2 \rightarrow f$

Let’s compute the derivative for each path.

___

**Path 1:** $w \rightarrow u_1 \rightarrow v_1 \rightarrow f$
Using the chain rule: $\frac{df}{dw} = \frac{\partial f}{\partial v_1} \cdot \frac{\partial v_1}{\partial u_1} \cdot \frac{\partial u_1}{\partial w}$

- $\frac{\partial f}{\partial v_1}$: How $f$ changes with $v_1$
- $\frac{\partial v_1}{\partial u_1}$: How $v_1$ changes with $u_1$
- $\frac{\partial u_1}{\partial w}$: How $u_1$ changes with $w$

___

**Path 2:** $w \rightarrow u_1 \rightarrow v_2 \rightarrow f$
Using the chain rule: $\frac{df}{dw} = \frac{\partial f}{\partial v_2} \cdot \frac{\partial v_2}{\partial u_1} \cdot \frac{\partial u_1}{\partial w}$

- $\frac{\partial f}{\partial v_2}$: How $f$ changes with $v_2$
- $\frac{\partial v_2}{\partial u_1}$: How $v_2$ changes with $u_1$
- $\frac{\partial u_1}{\partial w}$: How $u_1$ changes with $w$

___

**Combining Both Paths:**
Since both paths contribute to $\frac{df}{dw}$, we add the derivatives from both paths: $\frac{df}{dw} = \frac{\partial f}{\partial v_1} \cdot \frac{\partial v_1}{\partial u_1} \cdot \frac{\partial u_1}{\partial w} + \frac{\partial f}{\partial v_2} \cdot \frac{\partial v_2}{\partial u_1} \cdot \frac{\partial u_1}{\partial w}$

$\frac{\partial u_1}{\partial w} = x$: The change in $u_1$ with respect to $w$ is simply $x$ because $u_1 = w \cdot x$.

Thus, the formula simplifies to: $\frac{df}{dw} = x \left(\frac{\partial f}{\partial v_1} \cdot \frac{\partial v_1}{\partial u_1} + \frac{\partial f}{\partial v_2} \cdot \frac{\partial v_2}{\partial u_1}\right)$
## Keras Code
![[Pasted image 20250112212006.png|1000]]

![[Pasted image 20250112212044.png|400]]
# Quizzes
## Linear Regression
**Select all correct statements**
- Residuals are always between 0 and 1 ❌
- Residual plots show the residual values on the vertical axis ✅
- A residual for a sample is the difference between expected and predicted output value ✅
- Residuals are always between -1 and 1 ❌
- Residual plots always have the predicted value on the horizontal axis ❌

___

**Select all correct statements**
- The values of $R^2$ are always between -1 and 1 ❌
- The smaller the coefficient of determination R is, the better the regression model fits the data ❌
- The larger $R^2$, the closer the points scatter to the regression line ✅
- If a model always predicts the mean of all expected outcomes, then $R^2$ equals 0 ✅

___

**Select all correct statements**
- There exists a closed formula for univariate linear regression to compute the optimal values of $θ$ ✅
- There exists a closed formula for multivariate linear regression to compute the optimal values of $θ$ ✅
- $θ_0$ is a parameter of the hypothesis function ✅
- The goal of Linear Regression is to minimize the value of $h_θ(x)$ ❌
- The goal of Linear Regression is to minimize the value of $J(θ)$ ✅
- $θ_0$ is a parameter of the cost function ❌

___

**Select ALL properties that are always true for Multivariate Linear Regression, as we defined it in the pre-class reading**
- $x_0 = 0$ ❌
- $θ_0 < θ_1$ ❌
- $θ_0 ≥ 0$ ❌
- Sum of all variables $x_1$ to $x_n$ equals 1 ❌
- $x_0 = 1$ ✅
## Gradient Descent + Polynomial Regression
**Consider Multivariate Linear Regression with $m$ samples and each sample with $n$ features. How often is each sample $(x^{(i)}, y^{(i)})$ "touched" (used) in Gradient Descent?**
- At least $n$ times ❌
- Exactly $m$ times ❌
- Exactly once ✅
- At least $m$ times ❌
- At least once ❌
- None of the listed other answers ❌
- Exactly $n$ times ❌

___

**Assume that we run Gradient Descent 3 times, each time with the same learning rate $α$ and the same initial values of $θ$. Will this always result in the same solution?**
- This is not clear ❌
- Yes ✅
- No ❌

___

**We run Gradient Descent for Multivariate Linear Regression. Which of the following statements always are true?
- $h_θ()$ decreases in each iteration ❌
- None of the remaining statements is true ❌
- $α$ increases in each iteration ❌
- $h_θ()$ increases in each iteration ❌
- $J(θ)$ increases in each iteration 
- $α$ decreases in each iteration ❌
- $J(θ)$ decreases in each iteration ✅

___

**Which of the following statements about the given learning curve below are true?**
![[Pasted image 20250112213259.png|400]]

- The learning rate is good, run gradient descent as long as possible ❌
- The learning rate is probably too small ❌
- The learning rate is good, stop after 100 iterations ✅
- The learning rate is probably too large ❌

___

**Which of the following statements is correct?**
- For polynomial regression, we can reduce the risk of overfitting if we increase the degree of the polynomials ❌
- Regularization in polynomial regression is used to control the size of the learning rate $α$ ❌
- With hyperparameter tuning, we always explore all possible settings of the hyperparameters ❌
- The problem with overfitting is that the model might not generalize well to new datapoints ✅
## Logistic Regression
**Which of the following is/are instances of a classification problem? (Select all that apply)**
- Using hockey players' statistics to predict which of two teams will probably win a match ✅
- Inspecting a patient's medical record to estimate how many hours of exercise/sport they do per week. ❌
- Analyzing a song to determine if it is classical, techno, pop, or rock. ✅
- Analyzing a text to determine if the sentiment is happy or sad. ✅

___

**Which of the following is/are true of the logistic sigmoid function $g(z) = \frac{1}{1 + e^{-z}}$ (Select all that apply)**
- It never intersects the x-axis. ✅
- When used as part of logistic regression, the value g(z) can be interpreted as how “confident” the model is about its prediction. ✅
- It has an "s"-shape. ✅
- It jumps at the origin from a y value of 0 to a y value of 1. ❌
- It decreases from left to right. ❌

___

**Suppose that a logistic regression model produces an output $0.7$ for a given input $x$. What does this mean? (Choose the best single answer.)**
- The model is only slightly confident that x is positive. ✅
- The model is only slightly confident that x is negative. ❌
- The model is very confident that x is positive. ❌
- The model is very confident that x is negative. ❌

___

**Which of the following is/are true of the training process for logistic regression? (Select all that apply.)**
- The gradient descent update expressions are the same as for linear regression. ✅
- We can choose to use either the normal equation or gradient descent for training. ❌
- Instead of the residual sum of squares (RSS) cost function, we typically use the mean absolute error (MAE) function to optimize the model parameters. ❌

___

**In the context of training a logistic regression model, which of the following are hyperparameters? (Select all that apply.)**
- $θ_0, θ_1, …$ ❌
- Learning rate $α$ ✅
- Number of gradient descent iterations. ✅
- $J(θ)$ ❌
## Support Vector Machines
**Select all correct statements:**
- The hyperplane in the context of SVMs is a subspace of the feature space. ✅
- The distance between the hyperplane and every support vector in a maximal margin classifier is the same. ✅
- A sample $x(m)$ is classified based on a separating hyperplane given by $b + wTx$: The function $f(x(m)) = b + wTx(m)$ returns the probability that the sample $x(m)$ belongs to the positive class. ❌
- In a maximal margin classifier the margin is the average distance between the separating hyperplane and all samples. ❌

___

**Which of the following statements is correct?**
- There is always exactly one support vector ❌
- There are always exactly 2 support vectors ❌
- There are always at least 2 support vectors ✅
- There are always more than 2 support vectors ❌
- None of the above ❌

___

**Select all correct statements:**
- Slack variables are used to avoid overfitting ✅
- The sum of all slack variables is always 0 ❌ 
- If each sample has N features, then there will be N slack variables (one for each feature) ❌
- The slack variable for a misclassified sample will have a values > 1 ✅

___

**Assume that we have data that is not linearly separable. Select all options that might help to resolve this issue:**
- Use a polynomial kernel ✅
- Gather more training samples ❌
- Decrease the learning rate $α$ ❌
- Use an RBF kernel ✅

___

**Could a removal of a single training sample alter the position of the separating hyperplane fitted using the complete training dataset.**
- Yes ✅
- No ❌

___

**Assume you are to use a soft-margin SVM with an RBF kernel. How can you find good values for the hyperparameters C and $γ$? Select all that apply.**
- Random search using the performance of the model on the validation set ✅
- Grid search using the performance of the model on the test set ❌
- Manual search using the performance of the model on the training set ❌
- Grid search using the cross validation performance score ✅

___

**The decision boundary derived from a soft margin classifier is always linear.**
- True ✅
- False ❌
## Decision Trees
**If a decision tree is overfitting the training set, decreasing the max_depth is an option that can improve the situation.**
- True ✅
- False ❌

___

**The Gini impurity of a node where all samples belong to the same class is equal to zero.**
- True ✅
- False ❌

___

Calculate the Gini impurity of a node with the following distributions of samples per class

- Class 1: 15 Samples
- Class 2: 0 Samples
- Class 3: 23 Samples

Enter the value with a precision of three decimal places.

**Answer: 0.478** ✅

**→** Total samples: **15 + 0 + 23 = 38**

**→** Probabilities:
	- p1 $= 15/38 = 0.3947$
	- p2 $= 0/38 = 0$
	- p3 $= 23/38 = 0.6053$

**→** Gini $= 1 − (0.3947^2 + 0^2 + 0.6053^2) = 1 − (0.1558 + 0 + 0.3663) = 1 −0.5221 = 0.478$

___

**A node has maximal entropy if each class has the same number of samples.**
- True ✅
- False ❌

___

A leaf node has the following class distribution:

- Class 1: 42
- Class 2: 5

Calculate the probability it assigns to a prediction of the majority class. Enter the value as a number between 0 and 1, with a precision to two decimal places.

**Answer: 0.89** ✅

→ $42 + 5 = 47$ total instances
→ $42$ is the majority class
→ Probability $= \text{Probability} = \frac{\text{Number of instances in majority class}}{\text{Total number of instances}} = \frac{42}{47} = 0.893617$

___

A leaf node of a regression tree has samples with the following target values:

25, 32, 25, 42, 27

Calculate the prediction of this node with a precision of two decimal places.

**Answer: 30.2** ✅

→ Sum the values: $25 + 32 + 25 + 42 + 27 = 151$
→ Count the samples: $5$
→ Calculate the mean: $151/5 = 30.2$
## Neural Networks
**The decision boundaries of softmax regression are linear.**
- True ✅
- False ❌

___

**Given a neural network with 3 input nodes, 25 nodes in the hidden layer and 12 output nodes. How many trainable parameters does this network have (don't forget to count the bias term)?**

Answer: 412 ✅

→ Input layer to hidden layer:
Weights: 3 ∗ 25 = 75
Biases: 25
Subtotal: 100

→ Hidden layer to output layer:
Weights: 25 ∗ 12 = 300
Biases: 12
Subtotal: 312

→ Total: 100 + 312 = 412

___

**Select all correct statements:**
- A neural network always has exactly one node in the output layer. ❌
- The nodes in a neural network can have different activation functions. ✅
- The number of nodes in the first hidden layer of a neural network has to be equal to the number of input nodes ❌
- Neural networks with one hidden layer and ten neurons can approximate any continuous function. ❌
- The loss used in neural networks quantifies how much the predicted value differs from the true observed value. ✅

___

**Cross entropy is a cost function used in neural networks applied to address:**
- Classification problems. ✅
- Regression problems. ❌

___

**When applied on a regression task, the output layer of a neural network has a non-linear activation function.**
- True ❌
- False ✅

___

**When using gradient descent to minimize the cost function of a neural network we obtain a very close approximation to the global minimum.**
- True ❌
- False ✅
## Training Neural Networks
**Which of the following ingredients of a neural network is adapted during the network training process (gradient descent)?**
- The weights ✅
- The biases ✅
- Activation functions ❌
- Number of network layers ❌
- The values in the input nodes ❌

___

**An epoch is completed when the forward and backward pass are completed for all the samples in a batch.**
- True ❌
- False ✅

___

**The gradients in backpropagation are computed starting at the input layer of the network.**
- True ❌
- False ✅

___

**In backpropagation the final parameter updates are obtained by averaging the computed gradients over all training samples (in a batch).**
- True ✅
- False ❌

___

**Select all correct statements.**
- Backpropagation reuses computations from earlier steps for efficiency ✅
- Backpropagation updates the parameters of the network ✅
- Backpropagation is affected by the vanishing gradients problem ✅
- Backpropagation finds the global minimum of the cost function ❌

___

**Overfitting in neural networks can be addressed by (select all that apply):**
- Early termination of the training process ✅
- Increasing the number of iterations of gradient descent ❌
- Decreasing the learning rate ❌
- Increasing the depth of the network ❌
- Dropout ✅

___

**Dropout permanently removes randomly chosen nodes from the network.**
- True ❌
- False ✅
## Generative Models & Naive Bayes
**Imagine you are building a spam detection model using a Naive Bayes approach. You are analyzing emails based on the presence of two words: "offer" and "free." Your training data reveals the following:**

1. 50% of all emails are spam.
2. 70% of spam emails contain the word "offer."
3. 90% of spam emails contain the word "free."
4) 20% of non-spam emails contain the word "offer."
4. 5% of non-spam emails contain the word "free."

You receive a new email containing both the words "offer" and "free." **What is the joint probability of observing both of these words in an email, given that the email is spam?**

- 0.14 ❌
- 0.09 ❌
- 0.01 ❌
- 0.63 ✅

→ Joint probability: $P(\text{“offer”} \cap \text{“free”} \mid \text{Spam}) = P(\text{“offer”} \mid \text{Spam}) \times P(\text{“free”} \mid \text{Spam})$
→ Substitute given values:
	- $P(\text{“offer”} \mid \text{Spam}) = 0.7, \quad P(\text{“free”} \mid \text{Spam}) = 0.9$
	- $0.7 \times 0.9 = 0.63$

___

**Which of the following statements is TRUE about discriminative models?**
- They are better at generating synthetic data compared to generative models. ❌
- They learn the joint probability distribution of the features and labels. ❌
- They always assume that features are conditionally independent given the class label. ❌
- They focus on learning the decision boundary between classes. ✅

___

**Which of the following statements are TRUE about generative models in machine learning?**
- They aim to understand the underlying probability distribution of the data within each class. ✅
- They are generally less computationally complex than discriminative models. ❌
- They can be used to generate synthetic data by sampling from the learned probability distribution. ✅
- They primarily focus on learning the decision boundary between classes. ❌

___

Suppose you are trying to determine the probability of event A happening. You have some initial belief about how likely A is to occur. Then, you observe event B, which could potentially provide information about A. Bayes' Theorem provides a way to update your belief about A after considering the new evidence B.

The theorem states: $P(A|B) = (P(B|A) * P(A)) / P(B)$, where:

P(A|B): The updated probability of A after observing B (posterior probability).
P(B|A): The probability of observing B given that A has happened (likelihood).
P(A): The initial belief about the probability of A (prior probability).
P(B): The overall probability of observing B (evidence).

**Which of the following statements best describes how Bayes' Theorem updates the probability of event A after observing event B?**

- The updated probability of A is a weighted average of the initial probability of A and the likelihood of observing B given A. ❌
- The probability of A happening changes after we observe B. Observing event B changes how likely we think event A is. This change is based on how likely we thought A was before (initial belief of the probability of A) and how much evidence B provides about A. ✅
- Observing B always increases the probability of A. ❌
- The probability of A happening, given that B has already happened, depends on how likely B is to occur given that A happened. ❌

___

A manufacturing company aims to use a machine learning model for quality inspection to automatically identify different types of defects in manufactured parts. The company has a dataset of images of parts, each labeled with the defect type (e.g., scratch, crack, dent, missing component).

**Which model type is best suited for this task and why?**

- Discriminative model (logistic regression, neural network, SVM), because the goal is to accurately classify the defect type. ✅
- Generative model, because less data will be needed to build the model. ❌
- Generative model, because the company can understand the underlying causes of defects or generate synthetic images of defective parts for further analysis. ✅
- Discriminative model, because the goal is to find every possible defect, even defects not in the labels. ❌
## Clustering
**The total number of clusters K in K-means is automatically determined by the algorithm.**
- True ❌
- False ✅

___

**Different runs of K-Means can produce different clustering results.**
- True ✅
- False ❌

___

**How are the initial centroids selected in K-Means?**
- At the center of all data points ❌
- As randomly chosen points from RN ✅
- As randomly chosen points from the training set ✅
- At the origin $(0, 0, … ,0)$ ❌

___

**Which rule can be used to determine the optimal value for the total number of clusters “K”?**
- The knuckle rule ❌
- The wrist rule ❌
- The elbow rule ✅
- The ankle rule ❌

___

**DBSCAN is a soft clustering algorithm.**
- True ❌
- False, it's a hard clustering algorithm. ✅

___

**Which of the following are hyperparameters for DBSCAN?**
- $minPts$ ✅
- $ϵ$ ✅
- $γ$ ❌
- $α$ ❌
- $K$ ❌
- $M$ ❌
- $L$ ❌

___

**How are the starting/core points selected in the DBSCAN algorithm?**
- An unprocessed point closest to the center of all unprocessed points ❌
- An unprocessed point closest to the center of all data points ❌
- As random unprocessed point in the set of data points ✅
- The center of all unprocessed points ❌
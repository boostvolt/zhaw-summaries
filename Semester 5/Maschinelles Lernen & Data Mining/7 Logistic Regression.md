**Problem**
Linear Regression works for predicting continuous outcomes, but for classifying binary outcomes (e.g., whether someone loves _Troll 2_), we need a different approach.

**Solution**
Logistic Regression is used for binary classification. It fits an S-shaped curve to predict probabilities between 0 and 1, making it perfect for discrete outcomes like whether someone loves _Troll 2_. It also shares metrics like R² and p-values, and can mix discrete and continuous features for more accurate predictions.

Weaknesses
- **Assumes s-shaped relationship**: Assumes a simple, monotonic relationship between independent variable (e.g., Popcorn) and binary outcome (e.g., Loves _Troll 2_).
- **Fails with complex data**: Misclassifies data if the relationship is not s-shaped (e.g., mixed behavior in Popcorn consumption).
- **Inflexible**: Struggles when data doesn’t follow expected pattern, leading to poor predictions.
- **Alternative methods**: Decision Trees, Support Vector Machines, or Neural Networks can handle more complex relationships.

Given **M labeled training examples**, where each feature vector $x^{(i)}$ is N-dimensional, logistic regression uses the **sigmoid function** to convert linear predictions into probabilities: $\hat{y} = h_{\theta}(x) = g(\theta^T x) = \frac{1}{1 + e^{-\theta^T x}}$

![[Pasted image 20250112140118.png|800]]

The output $\hat{y}$ of logistic regression is always a **value between 0 and 1**. This value represents the **probability** that the sample belongs to the positive class.
- **Confident prediction**: $\hat{y} > 0.95$ or $\hat{y} < 0.05$
- **Uncertain prediction**: $0.4 < \hat{y} < 0.6$

![[IMG_1F913C25239C-1.png|Now that we know the probability that this person will love Troll 2, we can classity them as someone who either Loves Troll 2 or Does Not Love Troll 2. Usually the threshold for classification is 0.5... 1 = Loves Troll 2 Probability that someone loves Troll 2 and in this case, that means anyone with a probability of loving Troll 2 > 0.5 will be classified as someone who Loves Troll 2... and anyone with a probability ≤ 0.5 will be classified as someone who Does Not Love Troll 2. 0 = Does Not Love Troll 2 Popcorn (g) Thus, in this example, since 0.96 > 0.5, we'll classify this person as someone who Loves Troll 2 1 = Loves Troll 2 Probability that someone loves Troll 2 One last thing before we go: In this example, the classification threshold was 50%. However, when we talk about Receiver Operator Curves (ROCs) in Chapter 8, we'll see examples that use different classification thresholds. So get excited!!! TRIPLE BAM!!! Does Not 0 = Love Troll 2 X Popcorn (g)|800]]
# Probability vs. Likelihood
![[IMG_6AF39BCC5DA0-1.jpeg|5 0.06 Likelihood 0.00 Likelihoods are often used to evaluate how well a statistical distribution fits a dataset. For example, imagine we collected these three Height measurements.. 155.7 cm 155.7 cm First, we determine the Likelihoods, the y-axis coordinates on the curves, for each data point... 142.5 cm 155.7 cm 168.9 cm ...and we wanted to compare the fit of a Normal Curve that has its peak to the right of the data... 168.9 cm 142.5 cm and, by eye, we can see that, overall, the Likelihoods are larger when we center the curve over the data. 0.06 Likelihood 0.00 142.5 cm ..to the fit of a Normal Curve that is centered over the data. 155.7 cm 168.9 cm And larger likelihoods suggest that the centered curve fits the data better than the one shifted to the right. BAM!!! 155.7 cm 168.9 cm|800]]
# Fitting a Squiggle to Data
Unlike linear regression, logistic regression cannot use the **normal equation**. Instead, it relies on a **log-loss function** to optimize the model:

$\text{Log-Loss}(h_{\theta}(x), y) = \begin{cases} -\log(h_{\theta}(x)) & \text{if } y = 1 \\ -\log(1 - h_{\theta}(x)) & \text{if } y = 0 \end{cases}$

The log-loss function penalizes the model more for **confident but wrong predictions**. The final **cost function** is:

$J(\theta) = \frac{1}{M} \sum_{m=1}^{M} \text{Loss}(h_{\theta}(x^{(m)}), y^{(m)})$

![[Pasted image 20250112140227.png|400]]

Since the **log-loss** function is convex, we can use **gradient descent** to find the optimal parameters $\theta$.

**Update Rules:** $\theta_j = \theta_j - \alpha \frac{1}{M} \sum_{m=1}^{M} (h_{\theta}(x^{(m)}) - y^{(m)}) x_j^{(m)}$

Where:
- $\theta_j$: Parameter to update
- $\alpha$: Learning rate

![[IMG_3A60449E9C7F-1.jpeg|When we use Linear Regression, we fit a line to the data by minimizing the Sum of the Squared Residuals (SSR). n contrast, Logistic Regression swaps out the Residuals for Likelihoods (y-axis coordinates) and fits a squiggle that represents the Maximum Likelihood. Height Weight 1 = Loves Troll 2 Probability that someone loves Troll 2 0 = Does Not Love Troll 2 However, because we have two classes of people, one that Loves Troll 2 and one that Does Not Love Troll 2, there are two ways to calculate Likelihoods, one for each class. Popcorn (g) For example, to calculate the Likelihood for this person, who Loves Troll 2, we use the squiggle to find the y-axis coordinate that corresponds to the amount of Popcorn they ate... ...and this y-axis coordinate, 0.4, is both the predicted probability that they Love Troll 2 and the Likelihood. Likewise, the Likelihood for this person, who also Loves Troll 2, is the y-axis coordinate for the squiggle, 0.6, that corresponds to the amount of Popcorn they ate. 1 = Loves Troll 2 Probability that someone loves Troll 2 0 = Does Not Love Troll 2 = Loves Troll 2 ＝ Does Not Love Troll 2 1 = Loves Troll 2 - Probability that someone loves Troll 2 0 = Does Not Love Troll 2 Popcorn (g) Popcorn (g)|800]]

![[IMG_3717573260A0-1.jpeg|In contrast, calculating the Likelihoods is different for the people who Do Not Love Troll 2 because the y-axis is the probability that they Love Troll 2. The good news is, because someone either loves Troll 2 or they don't, the probability that someone does not love Troll 2 is just 1 minus the probability that they love Troll 2... 1 = Loves Troll 2 Probability that someone loves Troll 2 0 = Does Not Love Troll 2 = Loves Troll 2 = Does Not Love Troll 2 p(Does Not Love Troll 2) = 1 - p(Loves Troll 2) ...and since the y-axis is both probability and likelihood, we can calculate the Likelihoods with this equation. L(Does Not Love Troll 2) = 1 - L(Loves Troll 2) Popcorn (g) For example, to calculate the Likelihood for this person, who Does Not Love Troll 2 ..we first calculate the Likelihood that they Love Troll 2, 0.8. ...and then use that value to calculate the Likelihood that they Do Not Love Troll 2 = 1 - 0.8 = 0.2. 1 = Loves Troll 2 Probability that someone loves Troll 2 0 = Does Not Love Troll 2 1 = Loves Troll 2 Probability that someone loves Troll 2 0 = Does Not Love Troll 2 Bam! Popcorn (g) Popcorn (g)|800]]

![[IMG_A8C865C1FDF9-1.jpeg|Now that we know how to calculate the Likelihoods for people who Love Troll 2 and people who Do Not Love Troll 2, we can calculate the Likelihood for the entire squiggle by multiplying the individual Likelihoods together... and when we do the math, we get 0.02. 1 = Loves Troll 2 Probability that someone loves Troll 2 0 = Does Not Love Troll 2 0.4 × 0.6 × 0.8 × 0.9 × 0.9 × 0.9 × 0.9 × 0.7 × 0.2 = 0.02 Popcorn (g) vS. Now we calculate the Likelihood for a different squiggle... and compare the total Likelihoods for both squiggles. 1 = Loves Troll 2 - Probability that someone loves Troll 2 Does Not 0 = Love Troll 2 0.1 × 0.2 × 0.6 × 0.7 × 0.9 × 0.9 × 0.9 × 0.9 x 0.8 = 0.004 The goal is to find the squiggle with the Maximum Likelihood. In practice, we usually find the optimal squiggle using Gradient Descent. TRIPLE BAM!!! Popcorn (g)|800]]
## Underflow
![[IMG_89382258C222-1.jpeg|2 However, if the Training Dataset was much larger, then we might run into a computational problem, called Underflow, that happens when you try to multiply a lot of small numbers between 0 and 1. Technically, Underflow happens when a mathematical operation, like multiplication, results in a number that's smaller than the computer is capable of storing. Underflow can result in errors, which are bad, or it can result in weird, unpredictable results, which are worse. A very common way to avoid Underflow errors is to just take the log (usually the natural log, or log base e), which turns the multiplication into addition... log(0.4 × 0.6 × 0.8 x 0.9 x 0.9 x 0.9 x 0.9 x 0.7 x 0.2) = log(0.4) + log(0.6) + log(0.8) + 1og(0.9) + Iog(0.9) + 1og(0.9) + Iog(0.9) + log(0.7) + Iog(0.2) = -4.0 A ...and, ultimately, turns a number that was relatively close to 0, like 0.02, into a number relatively far from 0, -4.0.|800]]

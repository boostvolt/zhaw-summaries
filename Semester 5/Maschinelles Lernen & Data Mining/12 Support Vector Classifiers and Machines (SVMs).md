**Problem**
Given a set of data points that belong to two different classes, we want to find a boundary that separates these classes accurately. Simple linear models often fail when the data is not linearly separable in its original form.

**Solution**
This is addressed by **transforming the data into a higher-dimensional space** where a **linear boundary** (hyperplane) can effectively separate the classes. The SVM finds the optimal boundary that maximizes the margin between the classes for better generalization.

In **SVM binary classification**, we use the following notations:
- $X \in \mathbb{R}^{M \times N}$: The **feature matrix** with $M$ rows (training samples) and $N$ columns (features/dimensions).
- $y \in \{-1, +1\}^M$: The **label vector**, where:
	- -1 represents one class.
	- +1 represents the other class.

![[Pasted image 20250111151924.png|600]]
# Support Vector Classifier / Hyperplane
A **hyperplane** is a flat surface that separates data points in an N-dimensional space. It has **N-1 dimensions** in a space with N dimensions.
- **N = 2:** The hyperplane is a **line**
- **N = 3:** The hyperplane is a **plane**
- **N > 3:** The hyperplane is an **N-1 dimensional subspace**

![[Pasted image 20250111121443.png|300]]

![[IMG_851CD41D69E0-1.jpeg|One way to make a threshold for classification less sensitive to outliers is to allow misclassifications. For example, if we put the threshold halfway between these two people... ...then we'll misclassify this person as someone who does not love Troll 2, even though we're told that they do... ...but when a new person comes along... ...they will be classified as not loving Troll 2, which makes sense since they're closer to most of the people who do not love Troll 2. NOTE: Allowing the threshold to misclassify someone from the Training Data... ...in order to make better predictions.. ...is an example of the Bias-Variance Tradeoff mentioned in Chapter 1. By allowing for a misclassification, we avoid Overfitting the Training Data and increase the Bias a little, but we improve our predictions of new data, which suggests a reduction in Variance. = Loves Troll 2 = Does Not Love Troll 2 Alternatively, we could put the threshold halfway between these two people... ...however, this new threshold gives us the same result: one misclassification from the Training Data and the new person will be reasonably classified To be honest, the remaining combinations of pairs of points would give us similar results, so it's not super important which pair we pick. However, if we had a more complicated dataset, we could use Cross Validation to decide which pair of points should define the threshold and determine how many misclassifications of the Training Data to allow in order to get the best results.|800]]

![[IMG_9A6CB94701F0-1.jpeg|Now, imagine Cross Validation determined that putting a threshold halfway between these two points gave us the best results... However, if, in addition to measuring how much Popcorn people ate, we also measured how much Soda they drank, then the data would be 2-Dimensional Soda (ml) ...and a Support Vector Classifier would be a straight line. In other words, the Support Vector Classifier would be 1-Dimensional. then we would call this threshold a Support Vector Classifier. BAM. NOTE: Because we only measured how much Popcorn people ate... 10 Popcorn (g) If we measured Popcorn, Soda, and Age, then the data would be 3-Dimensional, and the Support Vector Classifier would be a 2-Dimensional plane. Popcorn (g) FO Soda (ml) ...the Support Vector Classifier, the threshold we use to decide if someone loves or does not love Troll 2, is just a point on a number line. Age Popcorn (g) And if we measured 4 things, then the data would be 4-Dimensional, which we can't draw, but the Support Vector Classifier would be 3-Dimensional. Etc., etc., etc.|800]]
## Hyperplane Equation
The general form of a hyperplane equation is: $b + w_1x_1 + w_2x_2 + \dots + w_Nx_N = 0$

Where:
- $b$: bias term
- $w$: weight vector
- $x$: input vector

For simplicity, it is written as: $b + \omega^T x = 0$
## Hyperplane Classification Rule
The hyperplane separates the data into two distinct classes based on this equation.
- If $b + \omega^T x > 0$: The point lies on one side of the hyperplane.
- If $b + \omega^T x < 0$: The point lies on the other side of the hyperplane.

The **sign of the output** determines the class, while the **magnitude** (distance from the hyperplane) indicates the confidence.
## Model Learning
The goal of SVMs is to find the **optimal weight vector** $w$ and **bias term** $b$ to correctly classify new data points using the prediction function: $f(x^*) = \hat{b} + \hat{w}^T x^*$

**Confidence of Predictions**
The **magnitude of the function output** represents the **confidence level** in the classification.
- **Far from zero**: High confidence in the prediction.
- **Close to zero**: Low confidence, meaning the point is near the decision boundary.
# Gutters
The **gutters** are the two **margin boundaries** on either side of the hyperplane.

The equations for the gutters are:
- $\hat{b} + \hat{w}^T x = 1$
- $\hat{b} + \hat{w}^T x = -1$

The **distance between the gutters** is: $\frac{2}{\lVert w \rVert}$
A **smaller** ($\lVert w \rVert$) increases the distance between the gutters, creating a **larger margin**.

![[Pasted image 20250111122428.png|600]]
# Classifiers
## Maximal (Hard) Margin Classifier
> [!WARNING] Warning
> Each point $x^{(m)}$ must be on the correct side of the hyperplane: $y^{(m)} \left(b + w^T x^{(m)}\right) \geq 1 \quad \forall m = 1, \dots, M$

Aims to find a **hyperplane** that **maximizes the margin** between two classes.
- **Margin**: The shortest distance from the hyperplane to the nearest data points of both classes.
- **Support Vectors**: The closest data points to the hyperplane that influence its position. These points are **equidistant** from the hyperplane.
- A **larger margin** leads to better **generalization** of the model.

The optimization goal is to **minimize** the norm of the weight vector $w$, while ensuring all points are correctly classified: $\min_{b,w} \frac{1}{2} \lVert w \rVert^2$

*This example is not solvable with Maximal Margin Classifier*
![[Pasted image 20250111130657.png|300]]
## Soft Margin Classifier
> [!WARNING] Warning
> In the Soft Margin Classifier, misclassified points or points within the margin can also become support vectors. The rule for classification is: $y^{(m)} \left(b + w^T x^{(m)}\right) \geq 1 - \epsilon_m, \quad \epsilon_m \geq 0$

Allows for **some violations** of the margin when the data is **not perfectly separable**. Unlike the **Hard Margin Classifier**, which requires all points to be on the correct side of the hyperplane, the Soft Margin permits **misclassifications** to improve **generalization**.

The Soft Margin Classifier minimizes both the **norm of the weight vector** and the **total slack**: $\min_{b,w,\epsilon} \frac{1}{2} \lVert w \rVert^2 + C \sum_{m=1}^{M} \epsilon_m$

 **Slack Variables**
- Measure how much a data point violates the margin.
- Larger slack values indicate greater violations, with $\epsilon_m > 1$ meaning the point is misclassified.

**Role of Regularization Parameter**
$C$ controls the **trade-off** between allowing **margin violations** and keeping the **margin wide**:
- Small $C$: Allows more violations → **Wider margin** → **Low variance, high bias**.
- Large $C$: Allows fewer violations → **Narrow margin** → **High variance, low bias**.

![[Pasted image 20250111130747.png|600]]
# Kernel Trick
The **Kernel Trick** is a method used to solve **non-linearly separable classification problems** by **mapping data into a higher-dimensional space**, where it becomes **linearly separable**.

**Why Use the Kernel Trick?**
- Some datasets cannot be separated with a straight line in the original feature space.
- By transforming the data into a **higher-dimensional space**, SVMs can find a linear separation in that space.

The transformation function $\phi(x)$ maps the original features to higher dimensions: $\phi(x) = \left(x_1^2, \sqrt{2}x_1x_2, x_2^2\right)$

![[Pasted image 20250111132951.png|300]] ![[Pasted image 20250111133006.png|300]]
## Kernel Functions
Instead of explicitly calculating the mapping function $\phi(x)$, the **Kernel Trick** uses a **kernel function** to compute the **dot product** in the transformed space **without directly computing the transformation**.

The **kernel function** $K(x^{(i)}, x^{(j)})$ replaces the dot product $x^{(i)T} x^{(j)}$ in the SVM optimization problem.

**Benefits of Using Kernels**
- **Efficient computations**: No need to work in the high-dimensional space explicitly.
- Only **pairwise comparisons** between points need to be computed, reducing complexity to $M^2$ operations.
### Linear Kernel
The **Linear Kernel** is simply the **dot product** of two input vectors: $K(x^{(i)}, x^{(j)}) = \sum_{n=1}^{N} x_n^{(i)} x_n^{(j)}$
- It results in a **linear decision boundary** in the original space.
- Used when data is **linearly separable**.

![[Pasted image 20250111133328.png|400]]
### Polynomial Kernel
> [!INFO] How do we find the best values for **r** and **d**?
> We just try a bunch of values and use **Cross Validation** to pick the best ones.

The **Polynomial Kernel** maps the input vectors into a **higher polynomial space**: $K(x^{(i)}, x^{(j)}) = (c + x^{(i)T} x^{(j)})^d$

Where:
- $c$: constant term
- $d$: polynomial degree

**With** $d = 1$ **and** $c = 0$, it becomes the **Linear Kernel**. It can create **non-linear decision boundaries** in the original space.

![[Pasted image 20250111133554.png|400]]

![[IMG_71DD57294858-1 Kopie.png|The Polynomial Kernel, which is what we used in the last example, looks like this... Polynomial Kernel: (ax b+ r)d ..where a and b refer to two different observations in the data... ..r determines the coefficient of the • polynomial.. ...and d determines the degree of the polynomial. (axb+r)d Popcorn? Popcorn Consumed (a)|800]]

![[IMG_1D2212BDE926-1.png|In the Popcorn example, we set r = 1/2 and d = 2.. and since we're squaring the term, we can expand it to be the product of two terms. Polynomial Kernel: (ax b + r)d ...and we can multiply both terms together... ...and then combine the middle terms... ...and, just because it will make things look better later, let's flip the order of the first two terms... ...and finally, this polynomial is equal to this Dot Product! = alb2 +: Zab+ Zab = azb2 + ab + 1 4 = ab + a2b2+. 1 4 = (a, az, ½) • (b, b2, z) 1 4 NOTE: Dot Products sound fancier than they are. A Dot Product is just (aa, 1) (6.b2,1) the first terms multiplied together. ab (a,a?, (b, 02/2) ...plus the second terms multiplied together. ab + a2b2 (a, a?, -Tr •(b, b2; Twi ab + a?b2+. 1 4 ..plus the third terms multiplied together. Bam.|800]]

![[IMG_1AA1F33098DD-1.png|To summarize the last page, we started with the Polynomial Kernel... ..set r = 1/2 and d = 2.. ...and, after a lot of math, ended up with this Dot Product.. ...and then StatSquatch learned that Dot Products sound fancier than they are.. so now we need to learn why we're so excited about Dot Products!!! (axb+r/8 = (axb+ 1) = (a, a3, 7) (6, 03, 1) Since a and b refer to two different observations in the data, the first terms are their x-axis coordinates.. la,a, 5 the second terms are their y-axis coordinates.. a, a? z)•10, b2: 금) and the third terms are their z-axis coordinates. Popcorn? Popcorn? Popcorn Consumed (g) Thus, we have x- and y-axis coordinates for the data. Popcorn Consumed (g) The x-axis coordinate is the amount of Popcorn consumed, and the y-axis coordinate is Popcorn?. (a, a? "2? However, since they are 1/2 for both points (and every pair of points we select), we can ignore them. (a, a? ) • (b, b2, (a, a? (b, b2 Popcorn? BAM!!! Popcorn Consumed (g) o00|800]]

![[IMG_65AF585E8FC4-1.jpeg|The reason Support Vector Machines use Kernels is that they eliminate the need to actually transform the data from low dimensions to high dimensions. Instead, the Kernels use the Dot Products between every pair of points to compute their high-dimensional relationships and find the optimal Support Vector Classifier. Popcorn- Popcorn? Popcorn Consumed (g) Popcorn Consumed (g) 11 For example, when r = 1/2 and d = 2.. we get this Dot Product.. 12 and since a and b refer to two different observations in the Training Data, we can plug their Popcorn values into the Dot Product and just do the math. (a xb + N) =(ax D+ =(a, a2, 2) •(b,b, 2) opcorn Consumed Umm... How do we find the best values for r and d? (a, a2 기) Just try a bunch of values and use Cross Validation to pick the best ones.|800]]

![[IMG_6894EC56EB32-1.jpeg|13 For example, if this person ate 5 grams of Popcorn... and this person ate 10 grams of Popcorn... Popcorn Popcorn Consumed (g) Opcorn Consumed (g) ...then we plug the values, 5 and 10, into the Dot Product. (a, a? ½) (b, b2 ...do the math. ...and we use this number, 2550.25. (5,53,) (10,103, 글)= (5 x 10)+ (52 x 102) + (글×글) = 2550.25 instead of the high-dimensional distance to find the optimal Support Vector Classifier. Umm... How does that work? 4 The relationships calculated by the Dot Products are used as input in a technique called the Lagrangian Multiplier Method, which is like Gradient Descent. Like Gradient Descent, the Lagrangian Multiplier Method is an iterative method that finds the optimal Support Vector Classifier one step at a time. Unfortunately, the details of how the Lagrangian Multiplier Method works are outside of the scope of this book. 15 Okay! Now that we understand most of the details of how Support Vector Machines and the Polynomial Kernel work, let's briefly get an intuition of how the Radial Kernel works. BAM!!!|800]]
### Radial Kernel (Radial Basis Function)
The **RBF Kernel** (also called **Gaussian Kernel**) is one of the most commonly used kernels. It maps data into an **infinite-dimensional space** and works well for **complex, non-linear problems**: $K(x^{(i)}, x^{(j)}) = \exp\left(-\gamma \lVert x^{(i)} - x^{(j)} \rVert^2\right)$

Where:
- $\gamma$: a **hyperparameter** that controls the **width** of the kernel.

![[Pasted image 20250111134102.png|400]]

**Effect of** $\gamma$ **on the Decision Boundary**
- **Large** $\gamma$ → Narrow kernel width → **Only points very close to each other** have a measurable influence → **Overfitting risk**.
- **Small** $\gamma$ → Wide kernel width → Points **far apart** still influence each other → **Underfitting risk**.

![[Pasted image 20250111134116.png|600]]

![[IMG_483C63537806-1.png|2 The basic idea behind the Radial Kernel is that when we want to classify a new person.. Earlier in this chapter, I mentioned that two of the most popular Kernel Functions for Support Vector Machines are the Polynomial Kernel and the Radial Kernel, which is also called the Radial Basis Function. Since we've already talked about the Polynomial Kernel, let's get an intuition about how the Radial Kernel works. Popcorn Consumed (g) ...we simply look to see how the closest points from the Training Data are classified. In this case, the closest points represent people who do not love Troll 2... The equation for the Radial Kernel might look scary, but it's not that bad. This Greek symbol y, gamma, scales how much influence neighboring points have on classification... ...and we find a good value for y (gamma) by trying a bunch of values and using Cross Validation to determine which is best... Popcorn Consumed (g) ...and thus, we classify the new person as someone who does not love Troll 2. e-r(a-b)2 ..and just like for the Polynomial Kernel, a and b refer to two different observations in the data. DOUBLE BAM!!! • Popcorn Consumed (g) BAM!!! Popcorn Consumed (g) Believe it or not, the Radial Kernel is like a Polynomial Kernel, but with r = 0 and d = infinity (axb+r)d = (axb + 0)00 ...and that means that the Radial Kernel finds a Support Vector Classifier in infinite dimensions, which sounds crazy, but the math works out. For details, scan, click, or tap this QR code to check out the StatQuest.|800]]
# Multiclass Classification
## One vs. (Rest) All
For **K classes**, train **K binary classifiers**, where each classifier distinguishes **one class vs. all others**.
The **unknown instance** is assigned to the class with the **highest confidence score** from the binary classifiers.

![[Pasted image 20250111150650.png|600]]
## One vs. One
For **K classes**, train **K(K-1)/2 binary classifiers** for **all pairwise comparisons** between classes.
The final classification is done by **majority voting** across all pairwise comparisons.

![[Pasted image 20250111150920.png|400]]
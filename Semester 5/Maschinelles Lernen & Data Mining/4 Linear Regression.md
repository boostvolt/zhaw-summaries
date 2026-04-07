**Problem**
Given a dataset with two continuous variables, the goal is to use one variable (e.g., X) to predict the other (e.g., Y).
1. How do we determine the best-fit line that represents the relationship between the variables?
2. How do we assess the confidence in our model’s predictions compared to a simple baseline, such as the mean of Y?

**Solution**
Linear Regression fits a line by minimizing the **Sum of Squared Residuals (SSR)**. It calculates **R²** to measure prediction accuracy and provides a **p-value** to assess confidence in the relationship. It’s the foundation for more advanced **Linear Models**.
# Simple (Univariate) Linear Regression
**Univariate regression** uses **one input variable (feature)** to predict the output.

The model learns two parameters:
- $\theta_0$: intercept (where the line crosses the y-axis).
- $\theta_1$: slope (rate of change in output for each unit increase in input).

Hypothesis Function: $h_{\theta}(x) = \theta_0 + \theta_1 x$

**Training a Univariate Regression Model**
- To find the best values for parameters $\theta_0$ and $\theta_1$ that minimize the prediction error.
- The model is trained using **labeled data** and optimizes parameters through a **loss function**.

Cost Function: $J(\theta_0, \theta_1) = \frac{1}{2M} \sum_{m=1}^{M} (y^{(m)} - \hat{y}^{(m)})^2$

Where:
- $M$: number of training samples
- $y^{(m)}$: true label for sample $m$
- $\hat{y}^{(m)}$: prediction for sample $m$

![[IMG_0E4FFD4DFBE4-1.png|Imagine we had Height and Weight • data on a graph Height ,.and we wanted to predict Height from Weight. Weight This line, which has a different y-axis intercept and slope, gives us slightly smaller residuals and a smaller SSR... Height Weight ...and this line has even smaller residuals and a • smaller SSR... Height Weight Because the heavier Weights are paired with taller Heights, this line makes terrible predictions. We can quantify how bad these predictions are by calculating the Residuals, which are the differences between the Observed and Predicted heights... Height Height Weight SSR- ...and using the Residuals to calculate the Sum of the Squared Weight Residuals (SSR). Then we can plot the SSR on this graph that has the SSR on the y-axis, and different lines fit to the data on the x-axis. .and this line has larger residuals and a larger SSR. Height As we can see on the graph, different values for a line's y-axis intercept and slope, shown on the x-axis, change the SSR, shown on the y-axis. Linear Regression selects the line, the y-axis intercept and slope, that results in the minimum SSR. BAM!!! Weight 77|800]]

![[IMG_5F899B7F3D7E-1.png|One way to find the lowest point in the curve is to calculate the • derivative of the curve (NOTE: If you're not familiar with derivatives, see Appendix D). If we don't change the slope, we can see how the SSR changes for different y-axis intercept values... ..and, in this case, the goal of Linear Regression would be to find the y-axis intercept that results in the lowest SSR at the bottom of this curve. Height SSR Height SSR- Weight Weight Height y-axis intercept Weight Height Height Weight Weight y-axis intercept ...and solve for where the derivative is equal to 0, at the bottom of the curve. Solving this equation results in an Analytical Solution, meaning, we end up with a formula that we can plug our data into, and the output is the optimal value. Analytical solutions are awesome when you can find them (like for Linear Regression), but they're rare and only work in very specific situations.|800]]
# Multiple (Multivariate) Linear Regression
**Multivariate regression** extends univariate regression to handle **multiple input features** (independent variables). Each input feature has its own parameter ($\theta$).

Hypothesis Function for Multivariate Regression: $h_{\theta}(x) = \theta_0 + \theta_1 x_1 + \theta_2 x_2 + \dots + \theta_N x_N$
Or, in **vectorized form**: $h_{\theta}(x) = \theta^T x$

Where:
- $X \in \mathbb{R}^{M \times (N+1)}$: feature matrix (including a column of ones for $\theta_0$)
- $\theta \in \mathbb{R}^{(N+1) \times 1}$: parameter vector
- $y \in \mathbb{R}^{M \times 1}$: output vector

![[IMG_C21387B84FB6-1.jpeg|2 However, it's just as easy to use 2 or more variables, like Weight and Shoe Size, to predict Height. Height = 1.1 + 0.5 x Weight + 0.3 x Shoe Size This is called Multiple Linear Regression, and in this example, we end up with a 3-dimensional graph of the data, which has 3 axes.. Just like for Simple Linear Regression, Multiple Linear Regression calculates R2 and p-values from the Sum of the Squared Residuals (SSR). And the Residuals are still the difference between the Observed Height and the Predicted Height. The only difference is that now we calculate Residuals around the fitted plane instead of a line. R2_SSR(mean) - SSR(fitted plane) SSR(mean) ...one for Height... Height ...and instead of a fitting a line to the data, we fit a plane. Shoe Size Weight •one for Weight... And when we use 3 or more variables to make a prediction, we can't draw the graph, but we can still do the math to calculate the Residuals for R2 and its p-value. ...and one for Shoe Size….. Bam.|800]]
# Analytical Solutions
## Closed-Form Solution
The **closed-form solution** is a direct method to calculate the optimal parameters $\theta$ by solving the derivatives of the **cost function**. It provides a formula to find the **global minimum** without iteration. Always converges to the **global minimum** because the hypothesis is a **convex function**.

**Formulas:** 
$\theta_0 = \mu_y - \theta_1 \mu_x$

$\theta_1 = \frac{\sum_{m=1}^{M} (x^{(m)} - \mu_x)(y^{(m)} - \mu_y)}{\sum_{m=1}^{M} (x^{(m)} - \mu_x)^2}$
## Normal Equation
The **normal equation** is another way to solve linear regression. It provides a solution without the need for gradient descent.

**Normal Equation Formula:** $\theta = (X^T X)^{-1} X^T y$

Where:
- $X$: input matrix
- $y$: output vector

**Steps:**
1. Construct the matrix $X$ and vector $y$.
2. Compute $\theta$ using the normal equation formula.
# Basic Assumptions
## Linearity
The relationship between the input features $X$ and the target variable $y$ must be **linear**.

![[Pasted image 20250111212234.png|600]]
## Independence
The outcome of one sample should not affect others.
## Normality
The **errors (residuals)** should follow a **normal distribution**.

![[Pasted image 20250111212253.png|600]]
## Homoscedasticity
The **error variance** should be **constant** across all input values.

![[Pasted image 20250111212313.png|600]]
# Derivatives
**Problem**
To understand the relationship between two variables (e.g., test scores and study time), we need a way to measure how one changes relative to the other.

**Solution**
The derivative provides a measure of change (rate of change) in one variable relative to another. It is calculated as the slope of a line that represents the relationship.
## Straight Line
The slope directly determines how y (e.g., Height) changes with x (e.g., Weight).

![[IMG_B459637A1B5F-1.png|Now let's stop talking about Studying and talk about Eating. This line has a slope of 3, and, regardless of how small a value for Time Spent Eating, our Fullness goes up 3 times Fullness that amount. Thus, the Derivative, the change in Fullness relative to the change in Time, is 3. d Fullness d Time = 3 Time Spent Eating|300]] 

![[IMG_3BAEDF4F2C8C-1.jpeg|When the slope is 0, and the y-axis value never changes, regardless of the x-axis value... Height of the Empire State Building ...then the Derivative, the change in the y-axis value relative to the change in the x-axis value, is 0. d Height d Occupants = 0 Number of Occupants 10 When the straight line is vertical, and the x-axis value never changes, then the Derivative is undefined. This is because it's impossible to measure the change in the y-axis value relative to the change in the x-axis value if the x-axis value never changes. y-axis x-axis|800]]
## Curved Line
If data is nonlinear, derivatives still help find the optimal curve fit by minimizing SSR at each point.

![[IMG_52993324F5CA-1.png|(11 Lastly, when we have a curved line instead of a straight line... 12 ...the Derivative is the slope of any straight line that just barely touches the curved line at a single point. Awesomeness Awesomeness Tangent Lines Slope = 5 Terminology Alert!!! A straight line that touches the curve at a single point is called a tangent line. Likes StatQuest Slope = 3 Likes StatQuest 13 Unfortunately, the Derivatives of curved lines are not as easy to determine as they are for straight lines. Awesomeness However, the good news is that in machine learning, 99% of the time we can find the Derivative of a curved line using The Power Rule (See Appendix E) and The Chain Rule (See Appendix F). Likes StatQuest|800]]
### Power Rule
Useful for polynomial regression.

![[IMG_B5B0677CC80E-1.png|Here we have a graph of how Happy people are relative to how Tasty the food is. Happiness Index and this is the equation for the squiggle: Happy = 1 + Tasty® d Happy d Tasty We can calculate the derivative, the change in Happiness with respect to the change in Tastiness = d Happy d Tasty YUM!!! Fresh, hot fries! YUM!!! by plugging in the equation for Happy. Tasty Food Index Cold, greasy fries from yesterday. Yuck. Happiness Index Tasty Index Now, when Tasty = -1, the slope of the tangent line is 3 d - 3 x Tasty? d Tasty = 3 x-12 = 3 d (1 + Tasty3) = d Tasty The constant value, 1, doesn't change, regardless of the value for Tasty, so the derivative with respect to Tasty is 0. d Tasty 0 d d Tasty Lastly, we recombine both terms to get the final derivative. Happy = 0 + 3 x Tasty2 = 3 x Tasty d d Tasty (1 + Tasty3) and taking the derivative of each term in the equation. d d Tasty d Tasty3 d Tasty The Power Rule tells us to multiply Tasty by the power, which, in this case is 3... d Tasty Tasty3 = 3 x Tasty3-1 = 3 x Tasty? ...and raise Tasty by the original power, 3, minus 1.|800]]
### Chain Rule
Handles nested functions or transformations.

![[IMG_1C52FED028ED-1.jpeg|Now imagine we measured how Hungry a bunch of people were and how long it had been since they last had a snack. Hunger So, we fit a quadratic line with an intercept of 0.5 to the measurements to reflect the increasing rate of Hunger. Hunger Likewise, we fit a square root function to the data that shows how Hunger is related to craving ice cream. Craves Ice Cream Hunger = Time? + 0.5 The more Time that had passed since *their last snack, the hungrier they got! Craves Ice Cream = (Hunger) 1/2 Hunger Time Since Last Snack Time Since Last Snack Now we want to see how Craves Ice Cream changes relative to Time Since Last Snack. Hunger Unfortunately, when we plug the equation for Hunger into the equation for Craves Ice Cream... Hunger =Time? + 0.5 Craves Ice Cream Craves Ice Cream = (Hunger) 1/2 Craves Ice Cream = (Time? + 0.5) 1/2 Bummer. Time Since Last Snack Hunger ...raising the sum by 1/2 makes it hard to find the derivative with The Power Rule. 299|800]]

![[IMG_68977DA858E1-1.jpeg|In the last part, we said that raising the sum by 1/2 makes it difficult to apply The Power Rule to this equation... Craves Ice Cream = (Time? + 0.5) 1/2 ...but there was an obvious way to link Time to Craves with Hunger, so we determined the derivative with The Chain Rule. However, even when there's no obvious way to link equations, we can create a link so that we can still apply The Chain Rule. 4 d Craves d Inside d Inside d Time Now we use The Power Rule to solve for the two derivatives... d Inside (Inside) 1/2 = 1/2 x Inside-1/2 1 2 x Inside1/2 d d Time • Time2 + 0.5 = 2 x Time First, let's create a link between Time and Craves Ice Cream called Inside, which is equal to the stuff inside the parentheses.. Inside = Time? + 0.5 ...and that means Craves Ice Cream can be rewritten as the square root of the stuff Inside. Craves Ice Cream = (Inside) 1/2 Now that we've created Inside, the link between Time and Craves, we can apply The Chain Rule to solve for the derivative. The Chain Rule tells us that the derivative of Craves with respect to Time... d Craves d Time d Craves 'X d Inside d Inside d Time ...is the derivative of Craves with respect to Inside. ...multiplied by the derivative of Inside with respect to Time. ...and just like when the link, Hunger, was obvious, when we created a link, Inside, we got the exact same result. BAM!!! and plug them into The Chain Rule d Craves d Time d Craves d Inside d Inside d Time d Craves d Time = 2 x Inside1/2 x (2 x Time) 2 x Time = 2 x Hunger1/2 d Craves d Time Time Hunger1/2 When there's no obvious link, we can make one out of stuff that is inside (or can be put inside) parentheses. DOUBLE BAM!!! 301|800]]
# Nearest Neighbor Regression
An **instance-based learning method** that predicts the output by calculating the **average of the** $k$ **nearest neighbors** in the dataset. The model finds the $k$ **closest data points** to a given input and takes their **average value** as the **predicted output**.

- **Instance-based** → The model **stores the training data** and makes predictions **based on the closest points**.
- The number of neighbors ($k$) is a **hyperparameter** that must be chosen.

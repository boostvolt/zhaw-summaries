**Problem**
Optimizing a model’s fit to the data is a key task in machine learning. While some problems have analytical solutions, many do not. For instance, there’s no analytical solution for Logistic Regression or Neural Networks, which require fitting complex patterns to data.

**Solution**
When an analytical solution is not available, Gradient Descent provides an effective alternative. It’s an iterative method that progressively refines guesses towards the optimal solution, used in a wide range of machine learning problems.

Gradient Descent is an **iterative optimization algorithm** used to minimize the **cost function** by updating the model parameters $\theta$ in the direction that reduces the error.

**Why Use Gradient Descent?**
- **Matrix multiplication** becomes too **time-consuming** or **numerically unstable** for large datasets (more than 20,000 samples).
- It avoids solving the **normal equation**, which can be inefficient for high-dimensional data.

**Steps of Gradient Descent**
1. **Initialize parameters** $\theta_0, \theta_1, \dots, \theta_n$ with random values.
2. **Iteratively update parameters** until convergence using the formula: $\theta_j = \theta_j - \alpha \frac{\partial}{\partial \theta_j} J(\theta)$
	- $\theta_j$: parameter to update
	- $\alpha$: learning rate
	- $J(\theta)$: cost function

> [!INFO] Will Gradient Descent always find the best parameter values?
> - **Local Minima Issue:** Gradient Descent may get stuck in a local minimum instead of reaching the global minimum.
> - **Challenges:** Since the SSR can’t always be graphed, we might not know we’re stuck in a local minimum.
> 
> Solutions
> 1. **Different Initializations:** Start with different random values for parameters to avoid local minima.
> 2. **Adjust Step Size:** Increase the step size to potentially escape local minima.
> 3. **Stochastic Gradient Descent:** The added randomness can help avoid local minima.

> [!INFO] Info
> In this example, Linear Regression could be solved analytically, but using Gradient Descent allows us to understand and evaluate its performance, especially in cases like Logistic Regression and Neural Networks where no simple analytical solution exists.
# Parameters
![[The StatQuest Illustrated Guide to Machine Learning 17.png|In the current example, we're trying to optimize the y-axis intercept. In machine learning lingo, we call the things we want to optimize parameters. So, in this case, we would call the y-axis intercept a parameter. Predicted Height = intercept + 0.64 x Weight If we wanted to optimize both the y-axis intercept and the slope, then we would need to optimize two parameters. tiny bam. Predicted Height = intercept + slope x Weight    Now that we know what we  mean when we say parameter,  let's see how Gradient Descent  optimizes a single parameter,  the intercept, one step at a  time!!! BAM!!!|800]]
# One Parameter
> [!INFO] Info
> While we use SSR in this example, Gradient Descent is a general iterative method and can be applied with different optimization techniques.

![[IMG_A57E43DD0EC6-1.png|In this first example, since we're only optimizing the y-axis intercept, we'll start by assigning it a random value. In this case, we'll initialize the intercept by setting it to 0. Height = 0 + 0.64 x Weight ...then we plug in the Observed values for Height and Weight for each data point. SSR = (Observed Heights - (0 + 0.64 x Weight1))2 + (Observed Height - (0 + 0.64 x Weightz))? + (Observed Height - (0 + 0.64 x Weight3))2 SSR = (1.4 - (0 + 0.64 × 0.5))2 + (1.9 - (0 + 0.64 × 2.3))2 + 13.2 - 10 + 0.64 × 2.9))2 Now, to calculate the SSR, we first plug the value for the y-axis intercept, 0, into the equation we derived in Steps 4 and 5... SSR = (Observed Height - (intercept + 0.64 x Weight1))2 + (Observed Height - (intercept + 0.64 × Weightz))2 + (Observed Height - (intercept + 0.64 × Weight3))2 SSR = (Observed Height - (0 + 0.64 x Weight1))2 + (Observed Height - (0 + 0.64 x Weightz))2 + (Observed Height - (0 + 0.64 × Weight))? Lastly, we just do the math. The SSR for when the y-axis intercept is set to 0 is 3.1. Bam! 1.12 + 0.42 + 1.32: = 3.1 87|800]]
## Loss / Cost Function
![[IMG_BCA92902FEF6-1.jpeg|Now, because the goal is to minimize the SSR, it's a type of Loss or Cost Function (see Terminology Alert on the right). In Gradient Descent, we minimize the Loss or Cost Function by taking steps away from the initial guess toward the optimal value. In this case, we see that as we increase the intercept, the x-axis of the central graph, we decrease the SSR, the y-axis. SSR TERMINOLOGY ALERT!!! The terms Loss Function and Cost Function refer to anything we want to optimize when we fit a model to data. For example, we want to optimize the SSR or the Mean Squared Error (MSE) when we fit a straight line with Regression or a squiggly line in Neural Networks). That said, some people use the term Loss Function to specifically refer to a function (like the SSR) applied to only one data point, and use the term Cost Function to specifically refer to a function (like the SSR) applied to all of the data. Unfortunately, these specific meanings are not universal, so be aware of the context and be prepared to be flexible. In this book, we'll use them together and interchangeably, as in "The Loss or Cost Function is the SSR." intercept 1 However, rather than just randomly trying a bunch of values for the y-axis intercept and plotting the resulting SSR on a graph, we can plot the SSR as a function of the y-axis intercept. In other words, this equation for the SSR... ...corresponds to this curve on a graph that has the SSR on the y-axis and the intercept on the x-axis. SSR = (1.4 - (intercept + 0.64 × 0.5))2 + (1.9 - (intercept + 0.64 × 2.3))2 + (3.2 - (intercept + 0.64 × 2.9))2 SSR Psst! Remember: these are the Observed Heights.. ...and these are the Observed Weights. intercept 88|800]]
## Derivatives
![[IMG_351B0D01A77D-1.png|12 Now, when we started with the y-axis intercept = 0, we got this SSR ..so how do we take steps toward this y-axis intercept that gives us the lowest SSR 13 The answers to those questions come from the derivative of the curve, which tells us the slope of any tangent line that touches it. NOTE: See Appendix D to learn more about derivatives. .and how do we know when to stop or if we've gone too far? SSR SSR 4 intercept A relatively large value for the derivative, which corresponds to a relatively steep slope for the tangent • line, suggests we're relatively far from the bottom of the curve, so we should take a relatively large step... SSR - intercept 15 A relatively small value for the derivative suggests we're relatively close to the bottom of the curve, so we should take a relatively small step SSR ...and a positive derivative tells us that we need to take a step to the left to get closer to the lowest SSR. ...and a negative derivative, or slope, tells us that we need to take a step to the right to get closer to the lowest SSR. intercept intercept <X In summary, the derivative tells us in which direction to take a step and how large that step should be, so let's learn how to take the derivative of the SSR!!! 89|800]]
## Chain Rule
![[IMG_CC3CFAF4EC27-1.jpeg|Because a single term of the SSR consists of a Residual. wrapped in parentheses and squared. one way to take the derivative of the SSR is to use The Chain Rule (see Appendix F if you need to refresh your memory about how The Chain Rule works). SSR = (: Height - (intercept + 0.64 x Weight) Step 1: Create a link between the intercept and the SSR by rewriting the SSR as the function of the Residual. Step 2: Because the Residual links the intercept to the SSR, The Chain Rule tells us that the derivative of the SSR with respect to the intercept is... SSR = (Residual)2 Residual = Height - (intercept + 0.64 x Weight) d SSR d intercept Step 3: Use The Power Rule (Appendix E) to solve for the two derivatives. d Residual d intercept a Residual a Residual (Residual) = 2 x Residual d SSR d Residual X d Residual d intercept Because of the subtraction, we can remove the parentheses by multiplying everything inside by -1. = d intercept Height - (intercept + 0.64 x Weight) = d intercept Height - intercept - 0.64 x Weight =0 - 1-0 = -1 Because the first and last terms do not include the intercept, their derivatives, with respect to the intercept, are both 0. However, the second term is the negative intercept, so its derivative is -1. Step 4: Plug the derivatives into The Chain Rule to get the final derivative of the SSR with respect to the intercept. d SSR d SSR d intercept d Residual * & Residual • = 2 x Residual x -1 d intercept BAM!!! = 2 x ( Height - (intercept + 0.64 × Weight) ) x -1 = -2 x ( Height - (intercept + 0.64 x Weight) ) Multiply this -1 on the right by the 2 on the left to get -2. 90|800]]

![[IMG_BE5B5C1688EC-1.jpeg|First, plug the Observed values into the derivative of the Loss or Cost Function. In this example, the SSR is the Loss or Cost Function.. so that means plugging the Observed Weight and Height measurements into the derivative of the SSR. d SSR = -2 x ( Height - (intercept + 0.64 x Weight) ) d intercept Height + -2 x ( Height - (intercept + 0.64 x Weight) ) + -2 x ( Height - (intercept + 0.64 x Weight) ) Weight d SSR =-2 x (:3.2:- (intercept + 0.64 x 2.9): ) d intercept + -2 x (:1.9:- (intercept + 0.64 x: 2.3): ) + -2 x (:1.4:- (intercept + 0.64 x: 0.5): ) Now we initialize the parameter we want to optimize with a random value. In this example, where we just want to optimize the y-axis intercept, we start by setting it to 0. d SSR = -2 x (3.2 - d intercept + -2 x 1.9- +-2 x (1.4- Height = intercept + 0.64 x Weight = 0 + 0.64 x Weight : (0 (0 + 0.64 × 2.9) ) + 0.64 × 2.3) ) + 0.64 × 0.5) )|800]]
## Step Size / Learning Rate
The **learning rate** ($\alpha$) controls how large the steps are during optimization.

Effect of Learning Rate:
- **Too small** → **Slow convergence** (takes too long to reach the minimum).
- **Too large** → **Divergence** or **overshooting** (jumps past the minimum).

A good strategy is to start with a **large learning rate** and **reduce it gradually** over time (called **decay**): $\alpha_t = \frac{\alpha_0}{1 + \text{decay\_rate} \times t}$
Other methods like **Adam** and **Adagrad** are commonly used for dynamic learning rates.

![[Pasted image 20250111172813.png|600]]

![[IMG_D0B8756C6D25-1.jpeg|Now evaluate the derivative at the current value for the intercept. In this case, the current value is O. d SSR • = -2 x (3.2 - d intercept + -2 x (1.9- +-2 x (1.4- When we do the math, we get -5.7 thus, when the intercept = 0, the slope of this tangent line is -5.7. + 0.64 × 2.9) ) + 0.64 × 2.3) ) + 0.64 × 0.5) ) = -5.7 SSR Now calculate the Step Size with the following equation: Gentle Reminder: The magnitude of the derivative is proportional to how big of a step we should take toward the minimum. The sign (+/-) tells us which direction. Step Size = Derivative x Learning Rate = -5.7 × 0.1 = -0.57 y-axis intercept NOTE: The Learning Rate prevents us from taking steps that are too big and skipping past the lowest point in the curve. Typically, for Gradient Descent, the Learning Rate is determined automatically: it starts relatively large and gets smaller with every step taken. However, you can also use Cross Validation to determine a good value for the Learning Rate. In this case, we're setting the Learning Rate to 0.1. Take a step from the current intercept to get closer to the optimal value with the following equation: Remember, in this case, the current intercept is 0. SSR New intercept = Current intercept - Step Size = 0 - (-0.57) = 0.57 The new intercept, 0.57, moves the line up a little closer to the data... y-axis intercept ...and it results in a lower SSR. Bam! 94|800]]
## Iteration
![[IMG_FF395880DB58-1.jpeg|Now repeat the previous three steps, updating the intercept after each iteration until the Step Size is close to 0 or we take the maximum number of steps, which is often set to 1,000 iterations. Evaluate the derivative at the current value for the intercept... d SSR - = -2 x (3.2 - (0.57 + 0.64 × 2.9) ) d intercept + -2 x (1.9 - (0.57 + 0.64 × 2.3) ) : = -2.3 := -2.3 +-2 x (1.4 - (0.57 + 0.64 × 0.5) ) SS y-axis inte b • Calculate the Step Size. Step Size = Derivative x Learning Rate = -2.3 × 0.1 = -0.23 NOTE: The Step Size is smaller than before because the slope of the tangent line is not as - steep as before. The smaller slope means we're getting closer to the optimal value. Calculate the new intercept value... New intercept = Current intercept - Step Size = 0.57 - (-0.23) = 0.8 SSR The new intercept, 0.8, moves the line up a little closer to the data... y-axis intercept ..and it results in a lower SSR. Double Bam!|800]]

![[IMG_A6122ACE8739-1.jpeg|After 7 iterations... a Evaluate the derivative at the current value... Calculate the Step Size... Calculate the new value... ...the Step Size was very close to 0, so we stopped with the current intercept = 0.95... ...and we made it to the lowest SSR. If, earlier on, instead of using Gradient Descent, we simply set the derivative to 0 and solved for the intercept, we would have gotten 0.95, which is the same value that Gradient Descent gave us. Thus, Gradient Descent did a decent job. SSR BAM??? y-axis intercept Not yet! Now let's see how well Gradient Descent optimizes the intercept and the slope!|800]]
# Two or More Parameters
![[IMG_0633607076F4-1.jpeg|Now that we know how to optimize the intercept of the line that minimizes the SSR, let's optimize both the intercept and the slope. Height = intercept + slope x Weight Height Weight Just like before, the goal is to find the parameter values that give us the lowest SSR. And just like before, Gradient Descent initializes the parameters with random values and then uses derivatives to update those parameters, one step at a time, until they're optimal. When we optimize two parameters, we get a 3-dimensional graph of the SSR. This axis represents . different values for the slope... ...the vertical axis is for the SSR and this axis represents different values for the intercept. 4 So, now let's learn how to take derivatives of the SSR with respect to both the intercept and the slope. SSR = ( Height - (intercept + slope x Weight) )2|800]]
## Chain Rule
![[IMG_8DF36E16B281-1.jpeg|The good news is that taking the derivative of the SSR with respect to the intercept is exactly the same as before. - We can use The Chain Rule to tell us how the SSR changes with respect to the intercept. SSR = (Height - (intercept + slope x Weight): 2 Step 1: Create a link between the intercept and the SSR by rewriting the SSR = (Residual)2 SSR as the function of the Residual. Step 2: Because the Residual links the intercept to the SSR, The Chain Rule tells us that the derivative of the SSR with respect to the intercept is...'..... Residual = Observed Height - (intercept + slope x Weight) d SSR d SSR d intercept d Residual Step 3: Use The Power Rule to solve for the two derivatives. d SSR a Residual = a Residual (Residual)? = 2 x Residual d Residual d intercept d Residual d intercept Because of the subtraction, we can remove the parentheses by multiplying everything inside by -1. = d intercept Height - (intercept + slope x Weight) = a intercept Height - intercept - slope x Weight d intercept = 0 - 1- 0 = -1 Step 4: Plug the derivatives into The Chain Rule to get the final derivative of the SSR with respect to the intercept. BAM!!! d SSR d intercept = d SSR d Residual 'X d Residual d intercept = 2 x Residual x -1 Because the first and last terms do not include the intercept, their derivatives, with respect to the intercept, are both 0. However, the second term is the negative intercept, so its derivative is -1. = 2 x ( Height - (intercept + slope x Weight) ) x -1 = -2 x ( Height - (intercept + slope x Weight) ) Multiply this -1 on the right by the 2 on the left to get -2. 9|800]]

![[IMG_FD4974000F1B-1.jpeg|2 The other good news is that taking the derivative of the SSR with respect to the slope is very similar to what we just did for the intercept. SSR = (: Height - (intercept + slope x Weight) Step 1: Create a link between the slope and the SSR by rewriting the SSR as the function of the Residual. Step 2: Because the Residual links the slope to the SSR, The Chain Rule tells us that the derivative of... the SSR with respect to the slope is. SSR = (Residual)2 We can use The Chain Rule to tell us how the SSR changes with respect to the slope. NOTE: A collection of derivatives of the same function but with respect to different parameters is called a Gradient, so this is where Gradient Descent gets its name from. We'll use the gradient to descend to the lowest SSR. Residual = Observed Height - (intercept + slope x Weight) Step 3: Use The Power Rule to solve for the two derivatives. d SSR d slope d SSR = d Residual d Residual d slope Because of the subtraction, we can remove the parentheses by multiplying everything inside by -1. d Residual d = d slope •d slope d = d slope Height - (intercept + slope x Weight) • Height - intercept - slope x Weight d SSR d Residual (Residual)2 = 2 x Residual d Residual = 0 - 0 - Weight = -Weight Step 4: Plug the derivatives into The Chain Rule to get the final derivative of the SSR with respect to the slope. DOUBLE BAM!!! d SSR d SSR d slope = d Residual* d Residual = 2 x Residual x -Weight d slope Because the first and second terms do not include the slope, their derivatives, with respect to the slope, are both 0. However, the last term is the negative slope times Weight, so its derivative is -Weight. = 2 x ( Height - (intercept + slope x Weight) ) x -Weight <. = -2 x Weight x ( Height - (intercept + slope x Weight) ) • Multiply this -Weight on the right by the 2 on the left to get -2 x Weight. 99|800]]

![[IMG_D3679A6DB32E-1.jpeg|Plug the Observed values into the derivatives of the Loss or Cost Function. In this example, the SSR is the Loss or Cost Function, so we'll plug the Observed Weight and Height measurements into the two derivatives of the SSR, one with respect to the intercept.. d SSR = -2 x ( Height - (intercept + slope x Weight1) ) d intercept + -2 x ( Height - (intercept + slope x Weightz) ) + -2 x ( Height - (intercept + slope x Weights) ) Height and one with respect to the slope. d SSR = -2 x (:3.2:- (intercept + slope x: 2.9):) d intercept + -2x (:1.9 - (intercept + slope x: 2.3): ) + -2 x (:1.4:- (intercept + slope x: 0.5):) Weight d SSR • = -2 x Weight x ( Height - (intercept + slope x Weight1) ) a slope + -2 x Weight x ( Height - (intercept + slope x Weightz) ) + -2 x Weight × ( Height - (intercept + slope x Weights) ) Gentle Reminder: The Weight and Height values that we're plugging into the derivatives come from the raw data in the graph. a SSR - = -2 x: 2.9::3.2:- (intercept + slope x: x:2.9):) d slope + -2 x: 2.3:1:1.9:- (intercept + slope x: 2.3):) + -2 x: 0.5::1.4 :- (intercept + slope x: 0.5):)|800]]

![[The StatQuest Illustrated Guide to Machine Learning 14.jpeg|Now initialize the parameter, or parameters, that we want to optimize with random values. In this example, we'll set the intercept to 0 and the slope to 0.5. Height = intercept + slope x Weight Height = 0 + 0.5 x Weight d SSR - = -2 x 3.2 - (intercept + slope x 2.9) ) d intercept + -2 x ( 1.9 - (intercept + slope x 2.3) ) + -2 x ( 1.4 - (intercept + slope x 0.5) ) ド d SSR _ = -2 x ( 3.2 - (0 :+:0.5 :× 2.9) ) d intercept + -2 x (1.9- : (0 :+:0.5 × 2.3) ) +-2 x (1.4 - : (0 +=0.5 =x 0.5) ) Height Weight d SSR d slope = -2 x 2.9 x (3.2 - (intercept + slope x 2.9) ) + -2 × 2.3 x ( 1.9 - (intercept + slope x 2.3) ) + -2 x 0.5 x ( 1.4 - (intercept + slope x 0.5) ) d SSR =-2 x 2.9 x 3.2- d slope +-2 x 2.3 x (1.9. +-2 x 0.5 x (1.4 . +: 0.5:× 2.9) ) : (0: +: 0.5:x 2.3) ) (0 +: 0.5 x 0.5) )|800]]
## Step Size / Learning Rate
![[IMG_9A24F92F0AEA-1.jpeg|Evaluate the derivatives at the current values for the intercept, 0, and slope, 0.5. d SSR =-2 x (3.2 - (0 + 0.5 × 2.9) ) d intercept +-2 x (1.9 - (0 + 0.5 × 2.3) ): = -7.3 + -2 x (1.4 - (0 + 0.5 × 0.5)) d SSR = -2 × 2.9 x ( 3.2 - (0 + 0.5 x 2.9) ) d slope + -2 x 1.9 x (2.3 - (0 + 0.5 × 1.9) ) + -2 x 0.5 x (1.4 - (0 + 0.5 x 0.5) ) =-14.8 Calculate the Step Sizes: one for the intercept .and one for the slope. Step Sizeintercept = Derivative x Learning Rate = -7.3 × 0.01 = -0.073 Take a step from the current intercept, 0, and slope, 0.5, to get closer to the optimal values.. Step Sizeslope = Derivative x Learning Rate = -14.8 × 0.01 = -0.148 NOTE: We're using a smaller Learning Rate now (0.01) than before (0.1) because Gradient Descent can be very sensitive to it. However, as we said earlier, usually the Learning Rate is determined automatically. New intercept = Current intercept - Step Sizeintercept = 0 - (-0.073) = 0.073 New slope = Current slope - Step Sizeslope and the intercept increases from 0 to 0.073, the slope increases from 0.5 to 0.648, and the SSR decreases. BAM! = 0.5 - (-0.148) = 0.648 102|800]]
## Iteration
![[IMG_F5ADA48901FC-1.png|And after 475 iterations... Evaluate the derivatives at their current values.. Calculate the Step Sizes... Calculate the new values... ...the Step Size was very close to 0, so we stopped with the current intercept = 0.95 and the current slope = 0.64... ...and we made it to the lowest SSR. If, earlier on, instead of using Gradient Descent, we simply set the derivatives to 0 and solved for the intercept and slope, we would have gotten 0.95 and 0.64, which are the same values Gradient Descent gave us. Thus, Gradient Descent did a great job, and we can confidently use it in situations where there are no analytical solutions, like Logistic Regression and Neural Networks. TRIPLE BAM!!! This axis represents different values for the slope... ...this axis is for the SSR... ...and this axis represents different values for the intercept.|800]]
# Gradient Descent Types
## Batch Gradient Descent (BGD)
The **gradient** is calculated on the **entire dataset**. Parameters are updated **after processing all samples**.

**Formula:** $\theta_j = \theta_j - \alpha \frac{1}{m} \sum_{i=1}^{m} \left( h_\theta(x^{(i)}) - y^{(i)} \right) x_j^{(i)}$

Where:
- $\theta_j$: parameter to be updated
- $\alpha$: learning rate
- $m$: number of training samples
- $h_\theta(x^{(i)})$: prediction for sample $i$
- $y^{(i)}$: true label for sample $i$

**Advantages**
- **Guaranteed convergence** for convex functions.
- Moves **smoothly** towards the minimum.

**Disadvantages**
- **Slow** for large datasets.
- **Requires a lot of memory** to hold the full dataset.

*Moves in a straight line towards the minimum.*
![[Pasted image 20250111173832.png|300]]
## Stochastic Gradient Descent (SGD)
Instead of using the **entire dataset**, SGD updates parameters **after each sample**. **Random shuffling** of data is often used to improve performance.

**Formula:** $\theta_j = \theta_j - \alpha \left( h_\theta(x^{(i)}) - y^{(i)} \right) x_j^{(i)}$

Where:
- The update is done **for each sample** $i$ rather than the whole dataset  

**Advantages**
- **Faster updates** compared to BGD.
- Can be used for **online learning**.

**Disadvantages**
- **High variance** in updates.
- The error function **fluctuates heavily**, making convergence harder to detect.

*Takes zig-zag steps to minimum due to high variance.*
![[Pasted image 20250111173904.png|300]]
## Mini-Batch Gradient Descent
> [!INFO] How to choose the size of a Mini-Batch?
> The effectiveness of Mini-Batch Stochastic Gradient Descent depends on available high-speed memory. More memory allows for larger Mini-Batches, speeding up training while maintaining efficiency.

Use a **batch of** $b$ **training samples** (where $1 \leq b \leq m$) to update parameters. **Typical mini-batch sizes:** 50 to 250 samples. **Balances** the benefits of BGD and SGD. Reduces **computational redundancy** while maintaining **stable updates**.

**Formula:** $\theta_j = \theta_j - \alpha \frac{1}{b} \sum_{i=1}^{b} \left( h_\theta(x^{(i)}) - y^{(i)} \right) x_j^{(i)}$

Where:
- $b$: batch size
- The update is done **after each mini-batch**, not the entire dataset.

**Advantages:**
- **More efficient** for large datasets.
- **Reduces variance** in updates.
- **Adaptable** to memory constraints.

*Balanced path to minimum — more stable than SGD but faster than BGD.*
![[Pasted image 20250111173936.png|300]]

![[The StatQuest Illustrated Guide to Machine Learning 15.jpeg|To see how Stochastic Gradient Descent works, let's go back to our simple example, where we want to fit a line to 3 data points. And just like with normal Gradient Descent, we start by initializing the intercept and slope of the line with random values. Height = 0 + 0.5 x Weight Height Height: Weight Weight 3 Now we randomly pick one point. In this case, we'll pick this one in the middle. Then, we evaluate the derivatives using just that single point... Height : d SSR - = -2 x (Height - (intercept + slope x Weight) ) d intercept d SSR = -2 x Weight x ( Height - (intercept + slope x Weight) ) d slope ...and then we calculate the Step Sizes... ...and then we calculate the new values. Weight|800]]

![[The StatQuest Illustrated Guide to Machine Learning 16.jpeg|Then we just repeat the last 4 steps until the Step Sizes are super small, which suggests we've optimized the parameters, or until we reach a maximum number of steps. BAM! Pick a random point from the dataset... their current values... Calculate the Step Sizes... TERMINOLOGY ALERT!!! Although a strict definition of Stochastic Gradient Descent says that we only select a single point per iteration, it's much more common to randomly select a small subset of the observations. This is called Mini- Batch Stochastic Gradient Descent. Using a small subset, rather than a single point, usually onverges on the optimal values in fewer steps and takes much less time than using all of the data. For example, if we had these data and wanted to use Mini-Batch Stochastic Gradient Descent... Height Weight Calculate the new values... ...then instead of randomly selecting one point per iteration, we might select 3 points.|800]]
# Univariate Linear Regression
In **univariate linear regression**, the goal is to minimize the **mean squared error (MSE)** by updating two parameters simultaneously:
- $\theta_0$ (intercept)
- $\theta_1$ (slope)

**Parameter Update Rules:** 
$\theta_0 = \theta_0 - \alpha \frac{1}{M} \sum_{m=1}^{M} (h_\theta(x^{(m)}) - y^{(m)})$

$\theta_1 = \theta_1 - \alpha \frac{1}{M} \sum_{m=1}^{M} (h_\theta(x^{(m)}) - y^{(m)}) x^{(m)}$

Where:
- $M$: number of training samples
- $h_\theta(x^{(m)})$: predicted value for sample $m$
- $y^{(m)}$: true label for sample $m$
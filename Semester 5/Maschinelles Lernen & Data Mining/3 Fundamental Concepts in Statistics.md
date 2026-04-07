# Histograms
**Problem**
When we have many measurements, visualizing trends is challenging because overlapping data points and hidden values obscure the insights.

![[Pasted image 20241226150940.png|Shorter 00000000000200 Paler Shorter 0-00008100000-Pater|800]]

**Solution**
Histograms divide the data range into **bins** and stack measurements falling into the same bin. This reveals trends like concentrations around the average or the rarity of extreme measurements, making hidden patterns visible.

> [!Warning] Limitations
> Histograms depend on the amount of data available. Limited data can make estimates unreliable or lead to empty bins.
> 
## Bins
The range of values is divided into intervals (bins). The height of each bar in the histogram represents the count of measurements within that bin.
- **Wide bins:** Oversimplify the data and obscure details.
- **Narrow bins:** Overcomplicate the data and emphasize noise.
- **Optimal bin size:** May require experimentation for clarity.

![[Pasted image 20241226151442.png|Shorter 00000C 000 ...and if the bins are too narrow, then they're not much help... If the bins are too wide, then they're not much help... Shorter 00 ...so, sometimes you have to try a bunch of different bin widths to get a clear picture. 00O Taller Shorter Taller Taller|800]]
## Probabilities
> [!Info] Confidence
> The more measurements available, the more confidence in probability estimates.

![[Pasted image 20241226151618.png|If we want to estimate the probability that the next measurement will be in this red box. ...we count the number of measurements, or observations, in the box and get 12. and divide by the total number of measurements, 19. Shorter Taller ...and we get 0.63. In theory, this means that 63% of the time we'll 12 get a measurement in the red = 0.63 box. However, the confidence we 19 .... have in this estimate depends on the number of measurements. Generally speaking, the more measurements you have, the more confidence you can have in the estimate. To estimate the probability that the next measurement will be in this red box, which only contains the tallest person we measured... •we count the number of measurements in the box and get 1 1 19 -:= 0.05 101088888 Shorter ...and divide by the total number of measurements, 19... Taller ...and the result, 0.05, tells us that, in theory, there's a 5% chance that the next measurement will fall within the box. In other words, it's fairly rare to measure someone who is really tall.|800]]

# Probability Distributions
**Problem**
Histograms require a lot of data to make precise probability estimates. Collecting this data can be time-consuming and expensive. Moreover, blank spaces in histograms create uncertainty when estimating probabilities.

**Solution**
Instead of relying solely on histograms, **Probability Distributions** use mathematical equations to approximate probabilities, reducing the need for extensive data collection.
## Descrete Probability Distributions
Describe scenarios where outcomes are countable and distinct (e.g., the number of successes, events, or items). 
Probabilities are assigned to specific, discrete values of a random variable.
### Binomial Distribution
Events with two possible outcomes (e.g., success/failure).

> [!INFO] (n - x)
> If **x** is the number of people who prefer pumpkin pie, and **n** is the total number of people, then **(n - x)** is the number of people who prefer blueberry pie.
> 

> [!INFO] q = (1 - p)
>  If **p** is the probability that someone prefer pumpkin pie, **(1 - p)** is the probability that someone prefers blueberry pie. Sometime people use **q = (1 - p)** and use **q** in the formula instead.

![[The StatQuest Illustrated Guide to Machine Learning 2.png|Now that we've looked at each part of the equation for the Binomial Distribution, let's put everything together and solve for the probability that 2 out of 3 people we meet prefer pumpkin pie. We start by plugging in the number of people who prefer pumpkin pie, x = 2, the number of people we asked, n = 3, and the probability that someone prefers pumpkin pie, p = 0.7... n! p(x = 2|n 3, p = 0.7) = p*(1 - p)"-x ...then we just do the math... 3! 2!3 - 2)! 0.7-(1 - 0.7)3-2 (Psst! Remember: the first term is the number of ways we can arrange the pie preferences, the second term is the probability that 2 people prefer pumpkin pie, and the last term is the probability that 1 person prefers blueberry pie.) = 3 × 0.7-x (0.3)1 ..and the result is 0.441, which is the same value we got when we drew pictures of the slices of pie. = 3 × 0.7 × 0.7 × 0.3 ;= 0.441 Gentle Reminder: We're using the equation for the Binomial Distribution to calculate the probability that 2 out of 3 people prefer pumpkin pie... 0.3 × 0.7 × 0.7 = 0.147 + 0.7 × 0.3 × 0.7 = 0.147 + 0.7 × 0.7 × 0.3 = 0.147 *= 0.441|800]]
### Poisson Distribution
Frequency of events over a fixed time or space unit (e.g., calls per hour, pages read per hour).

![[IMG_1B3885B3B13C-1.jpeg|For example, if you can read, on average, 10 pages of this book in an hour, then you can use the Poisson Distribution to calculate the probability that in the next hour, you'll read exactly 8 pages. NOTE: This 'e' is Euler's number, which is roughly 2.72. The equation for the Poisson Distribution looks super fancy because it uses the Greek - character 1, lambda, but lambda is just the average. So, in this example, 1 = 10 pages an hour. Now we just plug in the numbers and do the math... e-12x P(x = 8|2 = 10) = ＝ e- 10108 8! 22x p(x|2) = x! x is the number of pages we think we might read in the next hour. In this example, x = 8. ...and we get 0.113. So the probability that you'll read exactly 8 pages in the next hour, given that, on average, you read 10 pages per hour, is 0.113. e- 10108 8x7x6x5x4x3x2x1 = 0.113|800]]
## Continuous Probability Distributions
Describe scenarios where outcomes are measured on a continuous scale (e.g., time, height, weight). 
Probabilities are assigned to intervals rather than specific values, and the total area under the curve equals 1.
### Normal (Gaussian) Distribution
![[IMG_6FAF1A2400F6-1.png|The equation for the Normal Distribution looks scary, but, just like every other equation, it's just a matter of plugging in numbers and doing the math. 1 f(x/M, 0) : ＝ (x-M)}/202 2по? x is the x-axis coordinate. So, in this example, the x-axis represents Height and x = 50. The Greek character H, mu, represents the mean of the distribution. In this case, M = 50. To see how the equation for the Normal Distribution works, let's calculate the likelihood (the y-axis coordinate) for an infant that is 50 cm tall. Since the mean of the distribution is also 50 cm, we'll calculate the y-axis coordinate for the highest part of the curve. f(x= 50|= 50, 0= 1.5) = Now, we just do the math.... ＝ Lastly, the Greek character o, sigma, represents the standard deviation of the distribution. In this case, o = 1.5. 1 e (x-M)}/202 V 2no? 1 =e-(50-50)3(2x1.52) V2n1.52 1 e-034.5 V14.1 50 Height in cm. 1 ＝ V14.1 1 ＝ \ 14.1 = 0.27 ...and we see that the likelihood, the y-axis coordinate, for the tallest point on the curve, is 0.27. Remember, the output from the equation, the y-axis coordinate, is a likelihood, not a probability. In Chapter 7, we'll see how likelihoods are used in Naive Bayes. To learn how to calculate probabilities with Continuous Distributions, read on...|800]]

![[IMG_55A31B904962-1.png|For Continuous Probability Distributions, probabilities are the area under the curve between two points. Regardless of how tall and skinny... ...or short and fat a distribution is.. 142.5 cm 155.7 cm Height in cm For example, given this Normal Distribution with mean = 155.7 and standard deviation = 6.6, the probability of getting a measurement between 142.5 and 155.7 cm... There are two ways to calculate the area under the curve between two points: 168.9 cm ...is equal to this area under the curve, which in this example is 0.48. So, the probability is 0.48 that we will measure someone in this range. ...the total area under its curve is 1. Meaning, the probability of measuring anything in the range of possible values is 1. 4 One confusing thing about Continuous Distributions is that the while the likelihood for a specific measurement, like 155.7, is /'***• the y-axis coordinate and > O.. Likelihood = 4 ...the probability for a specific measurement is 0. 1) The hard way, by using calculus and integrating the equation between the two points a and b. f(x) dx < UGH!!! NO ONE' ACTUALLY DOES THIS!!! 2) The easy way, by using a computer. See Appendix C for a list of commands. Area = 0.48 BAM!!! 142.5 cm One way to understand why the probability is 0 is to remember that probabilities are areas, and the area of something with no width is 0. 155.7 cm 168.9 cm Another way is to realize that a continuous distribution has infinite precision, thus, we're really asking the probability of measuring someone who is exactly 155.7000000000000000000000 000000000000000 00000000000 000000000000000000 00000000... tall. 50|800]]
#### Cumulativ Distribution Function (CDF)
> [!INFO] Info
> Use the NORMDIST() function in Excel or Google Sheets.

![[IMG_2915905D918B-1.jpeg|1000|Putting everything together, we get 0.5 - 0.02 = 0.48. Gentle Reminder about the arguments for the NORMDISTO function: normdist ( x-axis value, mean, standard deviation, use CDF) nordist ( 155.7, 155.7, 6.6, I) - normdist ( 142.5, 155.7, 6.6, 1) = 0. 48 DOUBLE BAM!! 142.5cm 155.7cm 168.9cm 142.5cm 155.7cm 168.9cm|800]]
#### Probability vs. Likelihood
![[IMG_4F9092B6DE32-1.png|1000|Way back in Chapter 3, when we described the Normal Distribution, we saw that the y-axis represented Likelihood. More Likely The Normal Distribution's maximum likelihood value occurs at its mean. In this specific example, the y-axis represents the Likelihood of observing any specific Height. Less Likely Shorter For example, it's relatively rare to see someone who is super short... Average Height ...relatively common to see someone who is close to the average height... Taller ...and relatively rare to see someone who is super tall.|800]]

![[IMG_730327E12B97-1.png|1000|2 In contrast, later in Chapter 3, we saw that Probabilities are derived from a Normal Distribution by calculating the area under the curve between two points. 142.5 cm For example, given this Normal Distribution with mean = 155.7 and standard deviation = 6.6, the probability of getting a measurement between 142.5 and 155.7 cm... 155.7 cm Height in cm 168.9 cm ...is equal to this area under the curve, which, in this example, is 0.48. So, the probability is 0.48 that we will measure someone in this range. So, in the case of the Normal Distribution.. More Likely ...Likelihoods are the y-axis coordinates for specific points on the curve... ...whereas Probabilities are the area under the curve between two points. Less Likely 142.5 cm 155.7 cm 168.9 cm Lastly, in Chapter 3 we mentioned that when we use a Continuous Distribution, like the Normal Distribution, the probability of getting any specific measurement is always 0 because the area of something with no width is 0.|800]]
### Exponential Distribution
![[IMG_D8D4E04DE5CE-1.jpeg|Exponential Distributions are commonly used when we're interested in how much time passes between events. For example, we could measure how many minutes pass between page turns in this book. More Likely Less Likely|800]]
### Uniform Distribution
![[IMG_078A1C9A301B-1.jpeg|Uniform Distributions are commonly used to generate random numbers that are equally likely to occur. For example, if I want to select random numbers between 0 and 1, then I would use a Uniform Distribution that goes from 0 to 1, which is called a Uniform 0,1 Distribution, because it ensures that every value between 0 and 1 is equally likely to occur. More Likely Less Likely More Likely NOTE: Because there are fewer values between 0 and 1 than between 0 and 5, we see that the corresponding likelihood for any specific number is higher for the Uniform 0,1 Distribution than the Uniform 0,5 Distribution. More Likely Less Likely 0 1 0 In contrast, if I wanted to generate random numbers between 0 and 5, then I would use a Uniform Distribution that goes from 0 to 5, which is called a Uniform 0,5 Distribution. 5 Less Likely Uniform Distributions can span any 2 numbers, so we could have a Uniform 1,3.5 Distribution if we wanted one. 5|800]]
# Data Spread
> [!INFO] Population vs. Estimated
> Use the **population** when you have data for the entire population. Use the **estimated** when working with a subset of the population to make inferences.
## Mean
The **Mean** or average measurement tells us where the center of the curve goes.

> [!INFO] Estimated Mean
> The estimated mean, denoted as $\bar{x}$ (“x-bar”), is also called the **sample mean**.

![[IMG_ABDBFD25F17B-1.jpeg|20 Number of apples 2 Imagine we went to all 5,132 Spend-n-Save food stores and counted the number of green apples that were for sale. We could plot the number of green apples at each store on this number line... ...but because there's a lot of overlap in the data, we can also draw a Histogram of the measurements. 00001 40 DICO 20 Number of apples 40 If we wanted to fit a Normal Curve to the data like this.. ...then, first, we need to calculate the Population Mean to figure out where to put the center of the curve. 20 Because the Population Mean, M, is 20, we center the Normal Curve over 20. 40 5 Because we counted the number of green apples in all 5,132 Spend-n-Save stores, calculating the Population Mean, which is frequently denoted with the Greek character y (mu), is relatively straightforward: we simply calculate the average of all of the measurements, which, in this case, is 20. Sum of Measurements Population Mean = M = Number of Measurements 2+8+...+37 = = 20 5132 Now we need to determine with width of the curve by calculating the Population Variance (also called the Population Variation) and Standard Deviation. 20 40 20 40 278|800]]
## Variance / Variation
> [!WARNING] Estimated Variance
> We divide by **n - 1** instead of **n**.
> 
> $\text{Estimated Variance} = \frac{\sum (x - \bar{x})^2}{n - 1}$

![[IMG_A70E1A1D14EE-1.jpeg|In other words, we want to calculate how the data are spread around the Population Mean (which, in this example, is 20). The part in the parentheses, x - p, means we subtract the Population Mean, u, from each measurement, x. Population Variance = Population Variance Population Variance (x - M) For example, the first measurement is 2, so we subtract u, which is 20, from 2 ...then the square tells us to square each term... U) and the Greek character ≤ (Sigma) tells us to add up all of the terms... 0 н = 20 20 40 M = 20 (2 - 20) 20 (8 - 20) DO 40 (28 - 20) (2 - 20)2 (8 - 20)2 (28 - 20)2 (2 - 20)2 + (8 - 20)2 + ... + (28 - 20)2 Number of Measurements The formula for calculating the Population Variance is... Population Variance = ...which is a pretty fancy-looking formula, so let's go through it one piece at a time. Population Variance n ...and lastly, we want the average of the squared differences, so we divide by the total number of measurements, n, which, in this case, is all Spend-n-Save food stores, 5,132. 271|800]]

![[IMG_8445A5868B7A-1.jpeg|Now that we know how to calculate the Population Variance... ..when we do the math, we get 100. BAM? Nope, not yet. Population Variance L (x -u)º n (2 - 20)2 + (8 - 20)2 + •... + (28 - 20)2 5132 = 100 (10 Because each term in the equation for Population Variance is squared... the units for the result, 100, are Number of Apples Squared... .and that means we can't plot the Population Variance on the graph, since the units on the x-axis are not squared. M = 20 20 Number of apples 40|800]]
## Standard Deviation
This tells us how tall and skinny, or short and fat, the curve should be.

> [!WARNING] Estimated Standard Deviation
> We divide by **n - 1** instead of **n**.
> 
> $\text{Estimated Standard Deviation} = \sqrt{\frac{\sum (x - \bar{x})^2}{n - 1}}$

![[IMG_5369284447E8-1.png|11 To solve this problem, we take the square root of the Population Variance to get the Population Standard Deviation... Population Standard = Deviation (x - н)2 n = Population Variance (12 Now we have a graph that shows the Population Mean, 20, plus and minus the Population Standard Deviation, 10 apples, and we can use those values to fit a Normal Curve to the data. BAM!!! ..and because the Population Variance is 100, the Population Standard Deviation is 10... ...and we can plot that on the graph. H = 20 100 = 10 (13 M = 20 20 Number of apples 40 NOTE: Before we move on, I want to emphasize that we almost never have the population data, so we almost never calculate the Population Mean, Variance, or Standard Deviation. OXOX 20 Number of apples 40|800]]

![[IMG_52567A213B6F-1.png|= Infant = Adult The width of a Normal Distribution is defined by the standard deviation. In this example, the standard deviation for infants, 1.5, is smaller than the standard deviation for adults, 10.2... ...resulting in infants having a taller, thinner curve... ...compared to adults, who have a shorter, wider curve. 50 Because the mean measurement for infants is 50 cm, and 2 x the standard deviation = 2 x 1.5 = 3, about 95% of the infant measurements fall between 47 and 53 cm. 100 Height in cm. 150 Knowing the standard deviation is helpful because normal curves are drawn such that about 95% of the measurements fall between +/- 2 Standard Deviations around the Mean. Because the mean adult measurement is 177 cm, and 2 x the standard deviation = 2 x 10.2 = 20.4, about 95% of the adult measurements fall between 156.6 and 197.4 cm.|800]]
# Models
**Problem**
Building a precise histogram to represent data would be time-consuming and expensive. Collecting all possible data is often impractical.

**Solution**
A statistical, mathematical, or machine learning **Model** provides and approximation of reality that we can use.

- **Models** help explore relationships and make predictions, serving as approximations of reality.
- **Training Data** is used to build machine learning models via training algorithms.
- **Statistics** evaluate the usefulness and reliability of models.
## Sum of Squared Residuals (SSR)
**Problem**
We have a model that makes predictions. However we need to quantify the quality of the model and its predictions.

**Solution**
The **Sum of Squared Residuals (SSR)** provides a method to quantify model quality

> [!Info] Info
> The smaller the **SSR**, the better the model fits the data.

Residuals
- Residual = Observed value - Predicted value.
- Residuals represent the differences between actual data points and model predictions.

Square the Residuals
- Squaring ensures all differences are positive and avoids cancellation between over-predictions (positive Residuals) and under-predictions (negative Residuals).
- Squaring is also useful for mathematical optimization, such as **Gradient Descent** (for details, see [**Chapter 5**](obsidian://open?vault=obsidian&file=ZHAW%2FMaschinelles%20Lernen%20%26%20Data%20Mining%2F5%20Gradient%20Descent)).

> [!TIP] Formula
> $\sum_{m=1}^{M} \left(y^{(m)} - \hat{y}^{(m)}\right)^2$
> 
> $M$: Total number of samples (data points) in the dataset
>  $y^{(m)}$: Actual (true) value of the target variable for sample $m$
>  $\hat{y}^{(m)}$: Predicted value for sample $m$, generated by the model

![[The StatQuest Illustrated Guide to Machine Learning.png|SSR: Step-by-Step In this example, we have 3 Observations, son = 3, and we expand the summation into 3 terms. Observed = .•. Predicted = ... Residual = n The Sum of Squared - Residuals (SSR) =(Observed; - Predicted,)2 i=1 For i = 1, the term for the first Observation.. (1.9 - 1.7)2 2 Once we expand the summation, we plug in the Residuals for each Observation. SSR = (Observed - Predicted1)2 + (Observed - Predicted2)2 + (Observeds - Predicteds)2 For i = 2, the term for the second Observation... (1.6 - 2.0)2 3 Now, we just do the math, and the final Sum of Squared Residuals (SSR) is 0.69. SSR = (1.9 - 1.7)2 + (1.6 - 2.0)2 + (2.9 - 2.2)2 = 0.69 For i = 3, the term for the third Observation. (2.9 - 2.2)2|800]]
## Mean Squared Error (MSE)
**Problem**
The **Sum of Squared Residuals (SSR)** is influenced by the size of the dataset, making it difficult to compare models trained on datasets of different sizes.

For example
- Dataset 1 (3 points): Residuals = 1, -3, 2 → SSR = 14.
- Dataset 2 (5 points): Residuals = 1, -3, 2, -2, 2 → SSR = 22.

The increase in SSR does not necessarily mean the second model performs worse; it reflects the presence of more data.

**Solution**
Calculate the **Mean Squared Error (MSE)**, which normalizes the SSR by the number of data points, making it an average error measure that is easier to interpret and compare across datasets of varying sizes.

> [!Info] Info
> The smaller the **MSE**, the better the model fits the data.

> [!TIP] Formula
> $\frac{1}{M} \sum_{m=1}^{M} \left(y^{(m)} - \hat{y}^{(m)}\right)^2$
> 
> $M$: Total number of samples (data points) in the dataset
> $y^{(m)}$: Actual (true) value of the target variable for sample $m$
> $\hat{y}^{(m)}$: Predicted value for sample $m$, generated by the model

![[IMG_B7372DEB2F38-1.png|Mean Squared Error (MSE): Step-by-Step Now let's see the MSE in action by calculating it for the two datasets!!! Mean Squared Error (MSE) = SSR n n i=1 (Observedi - Predictedi)2 n The first dataset has only 3 points and the SSR = 14, so the Mean Squared Error (MSE) is 14/3 = 4.7. The second dataset has 5 points and the SSR increases to 22. In contrast, the MSE, 22/5 = 4.4, is now slightly lower. SSR n 14 3 = 4.7 Unfortunately, MSEs are still difficult to interpret on their own because the maximum values depend on the scale of the data. For example, if the y-axis is in millimeters and the Residuals are 1, -3, and 2, then the MSE = 4.7. SSR n 22 5 = 4.4 So, unlike the SSR, which increases when we add more data to the model, the MSE can increase or decrease depending on the average residual, which gives us a better sense of how the model is performing overall. However, if we change the y-axis to meters, then the Residuals for the exact same data shrink to 0.001, -0.003, and 0.002, and the MSE is now 0.0000047. It's tiny! millimeters 20 10 meters 0.02- 0.01-|800]]
## Root Mean Squared Deviation (RMSD)
> [!TIP] Formula
> $\sqrt{\frac{1}{M} \sum_{m=1}^{M} \left(y^{(m)} - \hat{y}^{(m)}\right)^2}$
> 
> $M$: Total number of samples (data points) in the dataset  
> $y^{(m)}$: Actual (true) value of the target variable for sample $m$  
> $\hat{y}^{(m)}$: Predicted value for sample $m$, generated by the model
## Mean Absolute Error (MAE)
> [!TIP] Formula
> $\frac{1}{M} \sum_{m=1}^{M} \left| y^{(m)} - \hat{y}^{(m)} \right|$
> 
> $M$: Total number of samples (data points) in the dataset  
> $y^{(m)}$: Actual (true) value of the target variable for sample $m$  
> $\hat{y}^{(m)}$: Predicted value for sample $m$, generated by the model
## R²
**Problem**
The **Mean Squared Error (MSE)** can be difficult to interpret because it depends on the scale of the data. For example, changing the units of measurement (e.g., from millimeters to meters) can drastically alter the **MSE**.

**Solution**
R² (R squared) is a simple, scale-independent metric that compares the performance of a model to the mean value of the data. It shows the percentage improvement in predictions made by the model, relative to just using the mean value. R² values range from 0 to 1, where higher values indicate better model fit.

 -  $0 \leq R^2 \leq 1$: However, in some cases, $R^2$ **can be negative**.
 - $R^2 = 1$: The model explains 100% of the variance in the target variable.
 - $R^2 = 0$: The model explains **none** of the variance (no better than predicting the mean).
 - $R^2 < 0$: The model performs **worse than a simple mean prediction**.

> [!INFO] Does R² always compare the mean to a straight fitted line?
> No, R² can compare any models using the Sum of Squared Residuals (SSR), like comparing square and sine waves for rainfall data.

> [!INFO] Can R² be negative?
> Yes, if comparing models other than the mean to a fitted line (e.g., straight line vs. parabola), R² can be negative.

> [!INFO] Is R² related to Pearson’s correlation coefficient?
> Yes, R² is the square of the Pearson correlation coefficient (ρ² = r² = R²).

![[IMG_A189EA6A2F8D-1.png|2 First, we calculate the Sum of the Squared Residuals for the mean. We'll call this SSR the SSR(mean). In this example, the mean Height is 1.9 and the SSR(mean) = 1.6. Height Then, we calculate the SSR for the fitted line, SSR(fitted line), and get 0.5. NOTE: The smaller Residuals around the fitted line, and thus the smaller SSR given the same dataset, suggest the fitted line does a better job making predictions than the mean. Height Weight SSR(mean) = (2.3 - 1.9)2 + (1.2 - 1.9)2 + (2.7 - 1.9)2 + (1.4 - 1.9)2 + (2.2 - 1.9)2 = 1.6 Now we can calculate the R2 value using a surprisingly simple formula... SSR(mean) - SSR(fitted line) SSR(mean) R2 = = 1.6 - 0.5 1.6 = 0.7 ...and the result, 0.7, tells us that there was a 70% reduction in the size of the Residuals between the mean and the fitted line. Weight SSR(fitted line) = (1.2 - 1.1)2 + (2.2 - 1.8)2 + (1.4 - 1.9)2 + (2.7 - 2.4)2 + (2.3 - 2.5)2 = 0.5 4 In general, because the numerator for R2... SSR(mean) - SSR(fitted line) ...is the amount by which the SSRs shrank when we fitted the line, R2 values tell us the percentage the Residuals around the mean shrank when we used the fitted line. When SSR(mean) = SSR(fitted line), then both models' predictions are equally good (or equally bad), and R2 = 0 SSR(mean) - SSR(fitted line) < SSR(mean) When SSR(fitted line) = 0, meaning that the fitted line fits the data perfectly, then R2 = 1. = SSR(mean) SSR(mean) - 0 SSR(mean) SSR(mean) SSR(mean) = 1 64|800]]

![[IMG_E068C82CFD84-1.jpeg|NOTE: Any 2 random data points have R2 = 1. ...because regardless of the Residuals around the mean.. ...the Residuals around a fitted line will be 0, and. SSR(mean) - 0 SSR(mean) = SSR(mean) = 1 SSR(mean) Because a small amount of random data can have a high (close to 1) R2, any time we see a trend in a small dataset, it's difficult to have confidence that a high Rz value is not due to random chance. If we had a lot of data organized randomly using a random ID Number, we would expect the graph to look like this. ..and have a relatively small (close to 0) R2 because the Residuals would be similar. In contrast, when we see a trend in a large amount of data like this... ..we can, intuitively, have more confidence that a large R2 is not due to random chance. Height VS. VS. ID Number ID Number ID Number Weight Weight Weight|800]]

> [!TIP] R² and MSE
> R² can also be calculated using the Mean Squared Error (MSE) instead of the Sum of Squared Residuals (SSR).
> 
> $$R^2 = \frac{MSE(\text{mean}) - MSE(\text{fitted line})}{MSE(\text{mean})}$$
## p-values
**Problem**
we often want to determine if there is a meaningful difference between two groups or variables. However, it’s difficult to know if observed differences are due to actual effects or just random chance.

**Solution**
P-values help quantify the confidence we have in the results. They provide a measure of how likely it is that the observed difference between groups happened by random chance.

> [!INFO] Threshold
> Common threshold for p-values is 0.05.

> [!INFO] Hypothesis Testing
> Hypothesis testing determines if there’s enough evidence to reject the null hypothesis, usually indicating no effect or difference. A p-value helps decide if the data suggests a significant result.

- **How p-values work**: A small p-value indicates strong evidence that there is a difference between the groups. The p-value ranges from 0 to 1, with values closer to 0 showing greater confidence.
- **False positives**: A p-value threshold of 0.05 means that 5% of the time, random chance might lead to a false positive (incorrectly concluding a difference exists when there is none).
- **Effect size vs. p-value**: A small p-value does not indicate how large the difference is between groups—just whether it exists. The actual size of the difference (effect size) can be small or large, even with a significant p-value.

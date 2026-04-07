**Problem**
We need a simple, fast method to classify data, especially with high-dimensional features like text.

**Solution**
Naive Bayes is effective here because it assumes feature independence, making it computationally efficient and less prone to overfitting compared to methods like decision trees.
# Multinomial Naive Bayes
Best suited for discrete data, such as text classification tasks like spam detection.

![[IMG_E9DE52E2F213-1.jpeg|There are several types of Naive Bayes algorithms, but the most commonly used version is called Multinomial Naive Bayes. 2 We start with Training Data: 8 messages that we know are Normal.. ...and 4 messages that we know are Spam. Then we make a histogram for all of the words in the Normal messages... ..and a histogram for all of the words in the Spam messages. 8 Dear Friend Lunch Money Dear Friend Lunch Money Now we calculate the probabilities of seeing each word given that they came from Normal messages. For example, the probability that we see the word Dear given (remember, - the vertical bar, I, stands for given) that we see it in Normal (N) messages... p( Dear N)= 8 17 = 0.47 p (Dear | N) = 0.47 p( Friend | N) = 0.29 p( Lunch | N) = 0.18 p(Money | N) = 0.06 ....is 8, the number of times Dear occurs in Normal messages, divided by the total number of words in the Normal messages, 17. and we get 0.47. Then we do the same thing for all the other words in the Normal messages.|800]]

![[IMG_DBF1CDDD51C5-1.jpeg|Then we calculate the probabilities of seeing each word given that they came from Spam messages. Dear Friend Lunch Money For example, the probability that we see the word Dear given that we see *p(Dear |S) = it in Spam (S) messages.. 2 7 = 0.29 p( Dear | S) = 0.29 p( Friend | S) = 0.14 p( Lunch | S) = 0.00 p( Money | S) = 0.57 ...is 2, the number of times Dear occurs in Spam messages divided by the total number of words in the Spam messages, 7 and we get 0.29. Then we do the same thing for all the other words in the Spam messages.|800]]
## Prior Probability
![[IMG_DBF1CDDD51C5-1 Kopie.jpeg|Now we calculate Prior Probabilities. In this context, a Prior Probability is simply a guess that we make without looking at the words in the message about whether or not a message is Normal or Spam. NOTE: The Prior Probabilities can be any pair of probabilities we want, but we usually derive them from the Training Data. For example, because 8 of the 12 messages are Normal, we let the Prior Probability for Normal messages, p(N), be 8/12 = 0.67 ...and because 4 of the 12 messages are Spam, we let the Prior Probability for Spam messages, p(S), be 4/12 = 0.33. p(N)=' # of Normal Messages = Total # of Messages 8 12 = 0.67 # of Spam Messages 4 p( S) = = Total # of Messages 12 = 0.33|800]]

![[IMG_FADD300CF225-1.png|(12 Now that we have the Prior Probability for Normal messages... P(N) = 0.67 ..and the probabilities for each word occurring in Normal messages... p( Dear | N) = 0.47 p( Friend | N) = 0.29 p(Lunch | N) = 0.18 p( Money | N) = 0.06 ..we can calculate the overall score that the message, Dear Friend, is Normal... p(N) x p(Dear | N) xp( Friend | N) = 0.67 × 0.47 × 0.29; = 0.09 by multiplying the Prior Probability that the message is Normal.. by the probabilities of seeing the words Dear and Friend in Normal messages... .and when we do the math, we get 0.09. ** Likewise, using the Prior Probability for Spam messages... p(S) = 0.33 ..and the probabilities for each word occurring in Spam messages... p( Dear | S) = 0.29 p( Friend | S) = 0.14 p( Lunch | S) = 0.00 p( Money | S) = 0.57 ...we can calculate the overall score that the message, Dear Friend, is Spam, and when we do the math, we get 0.01. p(S) x p(Dear S) x p(Friend | S) = 0.33 × 0.29 × 0.14;= 0.01|800]]

![[IMG_AED972B0620B-1.png|3 Now, remember the goal was to classify the message Dear Friend as either Normal or Spam... ...and we started with Training Data, 8 Normal and 4 Spam messages... ...and we created histograms of the words in the messages... Dear Friend Lunch Money p(Dear N) = 0.47 p( Friend | N) = 0.29 p( Lunch | N) = 0.18 p( Money N) = 0.06 ...and we used the histograms to calculate probabilities... Dear Friend Lunch Money p(Dear | S) = 0.29 p (Friend | S) = 0.14 p( Lunch S) = 0.00 p( Money | S) = 0.57 ...then, using the Prior Probabilities and the probabilities for each word, given that it came from either a Normal message or Spam, we calculated scores for Dear Friend.... p(N) xp( Dear N) x p( Friend | N) = 0.67 × 0.47 × 0.29 = 0.09 p(S) x p( Dear S) xp(Friend | S) = 0.33 x 0.29 × 0.14 = 0.01 P(N) = # of Normal Messages = 0.67 Total # of Messages p(S) = # of Spam Messages Total # of Messages = 0.33 ...and we calculated Prior Probabilities, which are just guesses that we make without looking at the contents of a message, that a message is either Normal or Spam.. ...and now we can finally classify Dear Friend!!! Because the score for Normal (0.09) is greater than Spam (0.01), we classify Dear Friend as a Normal message. Dear Friend BAM!!!|800]]

> [!INFO] Relation to Bayes’ Theorem
> Naive Bayes skips the denominator from Bayes’ Theorem, but you could do the extra math—it wouldn’t change the result.

![[Pasted image 20250110222637.png|800]]
## Pseudocounts
![[IMG_CC95AB9CAD60-1.jpeg|Missing data can pose a real problem for Naive Bayes or anything else based on histograms. As we saw in Chapter 3, we can easily have missing data if the Training Dataset is not large enough. A pseudocount is just an extra value added to each word, and usually adding pseudocounts means adding 1 count to each word. Here the pseudocounts are represented by black boxes. So, Naive Bayes eliminates the problem of missing data by adding something called a pseudocount to each word. NOTE: pseudocounts are added to every word in both histograms, even if only one histogram has missing data. Dear Friend Lunch Money After we add the pseudocounts to the histograms, we calculate the probabilities just like before, only this time we include the pseudocounts in the calculations. 8 + 1. p( Dear | N) = := 0.43 17 + 4: Dear Friend Lunch Money • p(Dear | N) = 0.43 p (Friend | N) = 0.29 p (Lunch N) = 0.19 p( Money | N) = 0.10 p( Dear S) = 0.27 p( Friend | S) = 0.18 p( Lunch | S) = 0.09 p( Money | S) = 0.45 Now the scores for this message are... Money Money Money Money Lunch p(N) X p( Money | N p(Lunch | N) = 0.67 × 0.104 × 0.19 = 0.00001 p(S) x p( Money|S )4 x p(Lunch | S) = 0.33 × 0.454 × 0.09 = 0.00122 5 Because Money Money Money Money Lunch has a higher score for Spam (0.00122) than Normal (0.00001), we classify it as Spam. SPAM!!!|800]]
# Gaussian Naive Bayes
Handles continuous data by assuming features follow a Gaussian (Normal) distribution.

> [!INFO] Flexibility with Distributions
> If the continuous data does not follow a Gaussian distribution, we can replace it with another appropriate distribution, like Exponential.

![[IMG_8FA35E069D52-1 1.jpeg| First we create Gaussian (Normal) curves for each Feature (each column in the Training Data that we're using to make predictions). Popcorn (grams) 24.3 28.2 etc. Soda Pop 7 533.2 etc. 2.1 4.8 etc. 120.5. •*$10.9 etc. mean = 220 sd = 100 Candy (grams) 50.5 etc. 90.7 102.3 etc. mean = 500 sd = 100 Starting with Popcorn, for the people who Do Not Love Troll 2, we calculate their mean, 4, and standard deviation (sd), 2, and then use those values to draw a Gaussian curve. mean = 4 sd = 2 Then we draw a Gaussian curve for the people who Love Troll 2 using their mean, 24, and their standard deviation, 4. mean = 24 sd = 4 Popcorn Popcorn (grams) 24.3 28.2 etc 2.1 4.8 •Etc Soda Pop (ml) 750.7 533.2 etc. 120.5 110.9 etc. Candy (grams) 0.2 50.5 etc. 90.7 102.3 etc. Likewise, we draw curves for Soda Pop... Popcorn (grams) Soda Pop (ml) 24.3 750.7 28.2 533.2 etc. etc.  2.1 120.5 4.8 110.9 etc. etc. Soda Pop Candy (grams) 0.2 50.5 etc. 90.7 102.3 etc. mean = 25 sd = 5 mean = 100 sd = 20 ...and for Candy. Candy|800]]
## Prior Probability
![[IMG_E433E4222A69-1.jpeg|Now we calculate the Prior Probability that someone Loves Troll 2. Just like for Multinomial Naive Bayes, this Prior Probability is just a guess and can be any probability we want. However, we usually estimate it from the number of people in the Training Data. In this case, the Training Data came from 4 people who Love Troll 2 and 3 people who Do Not Love Troll 2. p( Loves Troll 2) = * of People Who Love Troll 2 Total # of People 4 = 0.6 4+3 # Пф Then we calculate the Prior Probability that someone Does Not Love Troll 2... # of People Who Do Not Love Troll 2 p( Does Not Love Troll 2) = Total # of People = 0.4- 4 + 3 4 Now, when a new person shows up.. Popcorn ...and says they ate 20 grams of Popcorn. ...and drink 500 ml of Soda Pop → X Soda Pop ..and ate 100 grams of Candy. Candy|800]]
## Underflow
![[IMG_E0780CCE85FE-1.jpeg|...we calculate the score for Loves Troll 2 by multiplying the Prior Probability that they Love Troll 2... Popcorn p(Loves Troll 2) x L( Popcorn = 20 | Loves) k x L Soda Pop = 500 | Loves ) XL(Candy = 100 | Loves) « ...by the Likelihoods, the y-axis coordinates, that correspond to 20 grams of Popcorn, 500 ml of Soda Pop, and 100 grams of Candy, given that they Love Troll 2. Soda Pop X Candy "***** NOTE: When we plug in the actual numbers. p( Loves Troll 2) ••••• x L( Popcorn = 20 | Loves) "* x L( Soda Pop = 500 | Loves ) x L Candy = 100 | Loves) *•• we end up plugging in a tiny number for the Likelihood of Candy, because the y-axis coordinate is super close to o 0.6 * × 0.06 • × 0.004 x 0.000000000...001 and computers can have trouble doing multiplication with numbers very close to 0. This problem is called Underflow. To avoid problems associated with numbers close to O, we take the log (usually the natural log, or log base e), which turns the multiplication into addition. and turns numbers close to 0 into numbers far from 0. log(0.6 x 0.06 x 0.004 x a tiny number) = log(0.6) + log(0.06) + 1og(0.004) + log(a tiny number) =-0.51 + -2.8 + -5.52 + -115 = -124 ..and when we do the math, the score for Loves Troll 2 = -124. 131|800]]

![[IMG_588BC842E5E1-1.jpeg|Likewise, we calculate the score for Does Not Love Troll 2 by multiplying the Prior Probability... Popcorn p( No Love ) x L Popcorn = 20 | No Love ) x L Soda Pop = 500 | No Love ) • x L( Candy = 100 | No Love) ‹ Soda Pop X ...by the Likelihoods from the Does Not Love Troll 2 distributions for Popcorn, Soda Pop, and Candy. But before we do the math, we first take the log... Candy then we plug in the numbers, log( No Love )) do the math, and get -48. + log (Popcorn = 20 | No Love) •.... og(0.4) + log(a tiny number) + log(0.00008) + log(0.02) + log(L(Soda Pop = 500 | No Love) + log(L(Candy = 100 | No Love )) = -0.92 + -33.61 + -9.44 + -3.91 Lastly, because the score for Does Not Love Troll 2 (-48) is greater than the score for Loves • Troll 2 (-124), we classify this person... ...as someone who Does Not Love Troll 2. = -48 Log( Loves Troll 2 Score ) = -124 Log( Does Not Love Troll 2 Score ) = -48 DOUBLE BAM!!! Now that we understand Multinomial and Gaussian Naive Bayes, let's answer some Frequently Asked Questions.|800]]
# Mixed Naive Bayes
Combines Multinomial and Gaussian Naive Bayes to handle datasets with both discrete and continuous variables.

![[IMG_283BE7C93A29-1.png|Normal Dear Spam Dear For example, if we had word counts from Normal messages and Spam, we could use them to create histograms and probabilities... ...and combine those with Likelihoods from Exponential distributions that represent the amount of time that elapses between receiving Normal messages and Spam... Friend Lunch Money ...to calculate Normal and Spam scores for the message Dear Friend, received after 25 seconds elapsed, using both discrete and continuous data. log( Normal)) + log(p( Dear | Normal )) + log(p( Friend | Normal)) + log(L( Time = 25 | Normal )) Likelihood Time 24.3 28.2 etc. log( Spam )) + log(p( Dear | Spam )) + log( p( Friend | Spam )) + log(L( Time = 25 | Spam )) Likelihood Time between Normal messages Time 5.3 7.1 etc. Friend Lunch Money Time between Spam|800]]
# Probabilities Primer
## Sample Space & Events
**Sample Space (S)**
The set of all possible outcomes of an experiment.
Example: $S = \{\text{Heads, Tails}\}$

**Event**
Any subset of the sample space.
Example: Event of getting heads: $\{\text{Heads}\}$
## Probability of an Event
$P(A)$: The likelihood of event $A$ occurring.
$P(A)$ ranges between **0** (impossible) and **1** (certain).

Example: Probability of rolling a **6** on a die: $P(A) = \frac{1}{6}$.
## Axioms of Probability
**Non-Negativity**
$P(A) \geq 0$ for any event $A$.
Example: The chance of rolling a **7** with a six-sided die is **0**.

**Certainty**
The probability of the entire sample space (all possible outcomes) is **1**.
Example: $P(S) = 1$.

**Additivity:**
For events that cannot occur simultaneously (mutually exclusive events), the probability of either event occurring is the sum of their probabilities: $P(A \cup B) = P(A) + P(B)$

For **non-mutually exclusive events**, subtract the **intersection** to avoid double-counting: $P(A \cup B) = P(A) + P(B) - P(A \cap B)$
## Basic Set Operations in Probability
![[Pasted image 20250110222409.png|300]]

**Union (**$A \cup B$**)**
Either event $A$ or event $B$, or both, occur.

**Intersection (**$A \cap B$**)**
Both event $A$ and event $B$ occur.
For **independent events**: $P(A \cap B) = P(A) \cdot P(B)$

**Complement (**$A^c$**)**
The event that $A$ does **not** occur: $P(A^c) = 1 - P(A)$
## Joint and Conditional Probability
**Marginal Probability**
The probability of an event occurring without any conditions.
Example: Probability of rolling a **6**: $P(A) = \frac{1}{6}$.

**Joint Probability**
The probability of two or more events happening at the same time.
Example: $P(A \cap B)$.

**Conditional Probability**
The probability of event $B$ occurring given that event $A$ has already occurred: $P(B \mid A) = \frac{P(A \cap B)}{P(A)}$
## Law of Total Probability
The **Law of Total Probability** helps us calculate the probability of an event by considering all possible conditions or causes.

$P(A) = P(A \mid B_1)P(B_1) + P(A \mid B_2)P(B_2) + \dots + P(A \mid B_n)P(B_n)$
# Bayes' Theorem
Builds on the concept of **conditional probability** to update the probability of an event based on new evidence.

$P(A \mid B) = \frac{P(B \mid A) P(A)}{P(B)}$

Where:
- $P(A \mid B)$: **Posterior probability** — the probability of $A$ after observing $B$.
- $P(B \mid A)$: **Likelihood** — the probability of observing $B$ given $A$ is true.
- $P(A)$: **Prior probability** — the initial belief about $A$ before observing $B$.
- $P(B)$: **Evidence** — the overall probability of observing $B$.

**How This Fits into Naive Bayes**
The probability concepts above, particularly conditional probability and Bayes’ Theorem, are the mathematical foundations of the Naive Bayes algorithm. 

Here’s how:
- **Prior Probability:** $P(Y)$ — the probability of a class label.
- **Likelihood:** $P(X_i \mid Y)$ — the probability of observing a feature given the class.
- **Posterior Probability:** $P(Y \mid X)$ — the updated probability of a class label after observing the features.

The Naive Bayes classifier simplifies **Bayes’ Theorem** by assuming **independence** between features.
# Generative Models
## Generative vs. Discriminative Models
![[Pasted image 20250110235335.png|600]]

![[Pasted image 20250110235353.png|600]]

**Discriminative Models (e.g., SVM, Logistic Regression)**
- Learn a decision boundary to separate classes.
- Focus on modeling the relationship between features and labels.
- Example: Classifies data points directly without modeling data distribution.

**Generative Models (e.g., Naive Bayes)**
- Focus on understanding how the data is generated.
- Learn the joint probability distribution  P(X, Y)  and use it to calculate  P(Y|X)  for prediction.
- Based on probabilistic models.
- Example: Models how each class generates the data and then applies Bayes’ Theorem to classify.
## Likelihood Estimation and MLE
**Likelihood Estimation**
- Likelihood is a measure of how well a statistical model explains the observed data.
- Given a set of observed data $X$, the likelihood function calculates the probability of observing the data under specific parameter values $\theta$.

Example: For binary data sequences, the likelihood is calculated by multiplying individual probabilities.

**Maximum Likelihood Estimation (MLE)**
- MLE aims to find the parameter values that maximize the likelihood function: $\theta_{\text{MLE}} = \arg \max_{\theta} P(X|\theta)$
- Uses the **Negative Log-Likelihood (NLL)** to simplify calculations: $NLL(p) = -[\log(p) + \log(1 - p)]$
- Optimization involves taking the derivative of the log function and setting it to zero to find the optimal $p$ value.
## Maximum A Posteriori (MAP) Estimation
- MAP builds on MLE by incorporating prior knowledge about the parameters using **Bayesian principles**: $P(A|B) = \frac{P(B|A) \cdot P(A)}{P(B)}$
- MAP estimation includes a **prior probability** $P(\theta)$, unlike MLE, which only considers the likelihood: $\theta_{\text{MAP}} = \arg \max_{\theta} P(\theta|X) = \arg \max_{\theta} P(X|\theta) \cdot P(\theta)$
- The MAP estimation incorporates both the likelihood and prior knowledge about parameters.
## Generative Model Workflow
1. Learn the **joint probability distribution** for each class $P(X, Y)$.
	- $P(X|Y)$: Likelihood of observing features given a class label.
	- $P(Y)$: Prior probability of each class label.
2. Use **Bayes’ Theorem** to estimate the **posterior probability** for each class given new input data $P(Y|X)$.
3. **Prediction:** Assign the class label with the highest posterior probability.

Example: Given a new data point, calculate $P(Y|X)$ for each class and assign the label with the highest score.
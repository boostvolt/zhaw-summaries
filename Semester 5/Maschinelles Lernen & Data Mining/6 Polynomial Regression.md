An extension of linear regression that models the relationship between the independent variable $x$ and the dependent variable $y$ as a **polynomial function**. It is useful when the relationship between the variables is **non-linear**.

Instead of a simple linear hypothesis, a polynomial regression model uses a polynomial hypothesis: $h_\theta(x) = \theta_0 + \theta_1 x + \theta_2 x^2 + \theta_3 x^3 + \dots + \theta_n x^n$

To formalize this, we define **artificial variables**:
- $z_1 = x$
- $z_2 = x^2$
- $z_3 = x^3$

![[Pasted image 20250112121122.png|800]]

This transforms the polynomial function into a **linear combination** of the artificial variables: $h_\theta(z) = \theta_0 + \theta_1 z_1 + \theta_2 z_2 + \theta_3 z_3$

The **function remains linear** in terms of the coefficients $\theta$, but the input variables are polynomials.
# Regularization
Used to **prevent overfitting** by ensuring that the parameter values $\theta$ do not become too large. It adds a **penalty term** to the cost function:

$J(\theta) = \frac{1}{2m} \sum_{i=1}^{m} (y_m - h_\theta(x_m))^2 + \lambda \sum_{j=1}^{n} \theta_j^2$

Where:
- $\lambda$ **Regularization parameter (hyperparameter)**.
- The **larger** the value of $\lambda$, the **more penalty** is applied to large values of $\theta$, resulting in a **smoother curve**.
	- $\lambda$ close to zero: Parameters can take large values, increasing the risk of overfitting.
	- High $\lambda$: Keeps the curve smooth by reducing the impact of higher-degree terms.
# Hyperparameter Tuning
Finding the best combination of **hyperparameters** is crucial for building an optimal model. In polynomial regression, the key hyperparameters are:
- Regularization parameter $\lambda$
- Degree of the polynomial
- Learning rate $\alpha$

Hyperparameter Tuning Methods:
- **Manual Search:** Set hyperparameters manually.
- **Grid Search:** Try every possible combination of hyperparameter values.
- **Randomized Search:** Train models on random combinations of hyperparameters.
- **Genetic Algorithm:** Uses concepts from evolution like selection, crossover, and mutation to find optimal hyperparameters.
- **Bayesian Optimization:** Uses a probabilistic approach to search for the best hyperparameters.
# Model Complexity
- The goal is to **find the right balance** between bias and variance.
- **Regularization** helps reduce variance by keeping model complexity in check.
- **Error Formula:** $\text{Error} = \text{Bias}^2 + \text{Variance} + \text{Noise}$

![[Pasted image 20250112121025.png|600]]
## Bias
- Occurs when the model is **too simple** to capture the underlying pattern in the data.
- Results in **underfitting** (high bias, low variance).

![[Pasted image 20250112120902.png|600]]
## Variance
- Occurs when the model is **too complex**, fitting the **noise** in the training data.
- Results in **overfitting** (low bias, high variance).

![[Pasted image 20250112120945.png|600]]
# Feature Vector
Represents relevant properties of input data, typically as an n-dimensional vector of numbers.
## Images
Grayscale: Represented as a 2D array of pixel intensities (values between 0-1 or 0-255)

![[Pasted image 20250109224229.png|600]]

Color: Represented as a 3D array (stack of three 2D arrays for RGB channels)

![[Pasted image 20250109224247.png|600]]
## Audio
Use **Mel Frequency Cepstral Coefficients (MFCC)**:

1. Analyze audio in windows.
2. Compute log-energy in specific frequency bands based on human hearing.
3. Apply **Discrete Cosine Transform** to efficiently represent energy patterns.

![[Pasted image 20250109224307.png|600]]
## Text
**Bag of Words (BoW)**: Represent text by counting occurrences of words in a document.

![[Pasted image 20250109224403.png|600]]
# Algorithm Selection
**No Free Lunch Theorem**: No universally best algorithm exists; selection depends on the problem.
# Machine Learning Pipeline
![[Pasted image 20250109224754.png|600]]

1. **Data Collection & Preprocessing**
	- Data collection: Gather raw data
	- Cleaning: Handle missing or incorrect values
	- Normalization & Standardization: Scale data to comparable ranges
	- Encoding: Convert categorical data into numerical formats
	- Feature extraction: Identify relevant features
	- Dimensionality reduction: Reduce feature space to avoid overfitting

2. **Model Selection & Training**
	- Model Types: Linear regression, SVM, Decision Trees, etc.
	- Loss Functions: MSE, Cross-Entropy, Log Loss
	- Training Algorithms: Gradient Descent (batch or stochastic)
	- Hyperparameter tuning: Optimize model parameters for better performance

3. **Model Evaluation & Validation**
	- Evaluate model performance using metrics like:
		- Regression: MAE, MSE, R²
		- Classification: Accuracy, F1 Score

4. **Model Deployment & Monitoring**
	- Deployment: Implement on standalone applications or cloud platforms
	- App considerations: Requirements, complexity, and size
	- Monitoring: Continuously track model performance to ensure reliability
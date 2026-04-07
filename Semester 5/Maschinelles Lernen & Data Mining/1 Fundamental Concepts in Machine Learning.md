Machine Learning is a branch of AI and CS that uses data and algorithms to mimic human learning, improving accuracy over time. It has three core components:

1. **Decision Process**: Uses data to make guesses about patterns.
2. **Error Function**: Evaluates how accurate the guesses are and quantifies errors.
3. **Optimization Process**: Updates the model based on errors to refine decisions.

![[Pasted image 20250109143220.png|Understand Data Prepare Data Collect Data Working Time Train Model Deploy, Run, Monitor Operations Evaluate Optimize Computing]]
# Supervised Learning
We use a labeled dataset with **M training samples** and **N features** per sample. The data is structured as:
- **X:** Input matrix with dimensions  $M \times N$ (samples × features).
- **y:** Output vector with dimensions $M$ (one label per sample). 

![[Pasted image 20250109143635.png]]

The goal is to learn a function $f$ that maps inputs $X_m$ to predicted outputs $\hat{y}$ systematically.
## Classification
**Problem**
We have a big pile of data, and want to use it to make classifications.

E.g. We meet a person and want to **Classify** them as someone who likes **StatQuest** or not.

**Solution**
We can use our data to build a **Classification Tree** (for details, see [**Chapter 10**](obsidian://open?vault=obsidian&file=ZHAW%2FMaschinelles%20Lernen%20%26%20Data%20Mining%2F10%20Decision%20Trees)) to **Classify** a person as someone who will like **StatQuest** or not.

![[Pasted image 20241224141832.png]]
## Regression
**Problem**
We have another pile of data, and we want to use it to make quantitative predictions.

E.g. We measured the **Heights** and **Weights** of **5** different people. Because we can see a trend - the larger the value for Weight, the taller the person - it seems reasonable to predict Height using Weight. 

**Solution**
Using a method called **Linear Regression** (for details, see [**Chapter 4**](obsidian://open?vault=obsidian&file=ZHAW%2FMaschinelles%20Lernen%20%26%20Data%20Mining%2F4%20Linear%20Regression)), we can fit a line to the original data we collected and use that line to make quantitative predictions.

Thus, when someone new shoes up and tells us their **Weight**, we would like to use that information to predict their **Height**.

![[Pasted image 20241224144119.png|Height Weight]]
# Unsupervised Learning
Aims to uncover patterns or structure in unlabeled data $X$ , making evaluation less straightforward due to the absence of clear output labels.

![[Pasted image 20250109144007.png]]
## Clustering
Clustering involves grouping objects so that items in the same cluster are more similar to each other than to those in other clusters.
## Outlier Detection
Identifies samples that significantly differ from typical examples in the reference dataset, often used in fields like ITS, firewall, and virus detection.

![[Pasted image 20250109144154.png|600]]
# Reinforcement Learning
Involves an **agent** that observes the environment, performs actions, and receives rewards. The agent learns the best strategy by itself, guided by a policy that defines which action to take in a given situation.

![[Pasted image 20250109144330.png|600]]
# Variables
E.g. We use Weight, Shoe Size and Favorite Color to predict Height.

![[Pasted image 20241224142811.png|Weight Shoe Size Favorite Color Height 0.4 3 Blue 1.1 1.2 3.5 Green 1.9 1.9 4 Green 1.7 2.0 4 Pink 2.8 2.8 4.5 Blue 2.3]]
## Dependent Variable
Because our Height predictions depend on Weight, Shoe Size and Favorite Color measurements, we call **Heigh**t a **Dependent Variable**.
## Independent Variable / Feature
In contrast, because we're not predicting **Weight, Shoe Size and Favorite Color**, and thus they do not depend on Height, we call each an **Independent Variable** or a **Feature**.
# Data
## Structured Data
Data that is organized in a predefined manner, typically in rows and columns, making it easy to store, search, and analyze.

**Examples**
- **Spreadsheets and databases:** Information organized in tables with clearly defined rows and columns.
- **Customer databases:** Information such as names, addresses, and phone numbers, typically stored in relational databases like SQL.
## Semi-Structured Data
Data that doesn’t fit neatly into tables but still has some organizational properties, often represented in formats like JSON, XML, or NoSQL databases.

**Examples**
- **Emails:** The body of the email is unstructured, but fields like sender, recipient, and subject follow a defined structure.
- **Web pages:** HTML tags provide structure, but the content itself may vary widely.
- **XML and JSON files:** Both allow flexible data organization but retain a hierarchy of tags or keys for easier processing.
## Unstructured Data
Data that lacks a predefined structure or format, making it more difficult to analyze and interpret without processing or analysis techniques.

**Examples**
- **Text files:** Raw text without specific formatting or structure.
- **Images and videos:** Visual or multimedia content with no inherent data structure.
- **Audio recordings:** Unprocessed sound data that requires analysis to extract meaningful information.
## Metadata
Data that describes other data, providing context or additional information about the main data.

**Examples**
- **File properties:** Information like file size, file type, and creation date.
- **Web page metadata:** Tags like title, keywords, and description in HTML to describe the content of a page.
- **Database metadata:** Information about the structure of a database, such as table definitions, column types, and relationships between tables.
## Categorial
### Nominal
Categorical data that cannot be quantified or ranked, and there is no inherent order between the categories.

**Examples**
- **Gender:** Categories like male, female, and non-binary with no ranking between them.
- **Hair color:** Categories like brown, blonde, black, and red with no order.
- **Marital status:** Categories like single, married, divorced, and widowed without a specific order.
### Ordinal
Discrete data with a meaningful order, but no defined distance between the categories.

**Examples**
- **Military rank:** Categories like private, sergeant, lieutenant, etc., where the order matters but the difference in rank between categories isn’t quantified.
- **Movie rating by stars:** Categories like 1 star, 2 stars, 3 stars, etc., where the order matters, but the difference in quality between ratings is not precisely defined.
- **Education level:** Categories like high school, bachelor’s degree, master’s degree, where the order matters but the exact difference in knowledge or skill between them isn’t measurable.
## Numerical
### Discrete Data
Countable and only takes specific values.

**Examples**
- **Number of people that love the color green:** Counting individual people, and the total can only be whole numbers.
- **American shoe sizes:** There are half sizes like 8 1/2, but never 8 7/36 or 9 5/18.
- **Ranking and other orderings:** There is no award for coming in 1.68 place.
### Continuous Data
Measurable and can take any numeric value within a range.

> [!INFO] Precision
> The precision of Continuous measurements is only limited by the tools we use.

**Examples**
- **Height measurements:** Can be any number between 0 and the height of the tallest person. (If we get more precise ruler, then the measurements get more precise)
## Training Data
The original dataset used to observe trends and fit a machine learning model.

![[Pasted image 20241224180231.png|Values Values Values Time Time Time Underfitted Good Fit/Robust Overfitted|800]]
### Overfitting
Occurs when a model fits the **Training Data** too closely, capturing noise rather than the general pattern. This leads to poor predictions on new data.

Closely related to the **Bias-Variance Tradeoff**
- **Bias:** A model with high bias makes overly simplistic assumptions, leading to underfitting. It fails to capture the complexity of the data, resulting in consistently poor predictions.
- **Variance:** A model with high variance adapts too much to the Training Data, including its noise, leading to overfitting.

The goal is to balance bias and variance for optimal model performance. This balance ensures that the model generalizes well to new data without being too rigid or overly flexible.
### Underfitting
Happens when a model is too simple to capture the patterns in the **Training Data**, resulting in both poor training and testing performance.
## Testing Data
A separate dataset used to evaluate the performance of a machine learning model.

**Evaluation Process**
1. Predictions are made for the **Testing Data** (blue dots) using the trained model.
2. Errors are measured by comparing predicted values to observed values in **Testing Data**.
3. Total errors for different models (e.g., black line vs. green squiggle) are summed and compared.
4. The model with lower total error is considered better at making predictions.

![[Pasted image 20241224180439.png|X Weight X Weight Second Error First Error Total Error|800]]

![[Pasted image 20241224180315.png|X Weight X Weight Second Error First Error Total Error|800]]

> [!Info] Info
> The black line, despite fitting **Training Data** (red dots) less perfectly, generalized better to **Testing Data** (blue dots), making it the better choice for prediction.

![[Pasted image 20241224180814.png|Total Green Squiggle Errors Total Black Line Errors Height Weight Height Weight|800]]

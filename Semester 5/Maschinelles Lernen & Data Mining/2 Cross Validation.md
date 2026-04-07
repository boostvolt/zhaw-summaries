**Problem**
Usually no one tells is which data points are for **Training** and which are for **Testing**. 

**Solution**
Cross Validation solves this by iteratively using all data points for both **training** and **testing** in an unbiased way.

> [!Info] Data Leakage
> Reusing the same data for both training and testing is called **Data Leakage**. Leads to overfitting and poor generalization to new, unseen data.
# Leave-One-Out Cross Validation (LOOCV)
**Concept:** Each iteration uses all data points except one for training, and the excluded point for testing.
**Use Case:** Best for small datasets where every data point is valuable.

**Advantages**
- Maximizes training data in each iteration.
- Prevents biased evaluations.

**Disadvantages**
- Computationally expensive for large datasets.

![[Bildschirmfoto 2024-12-25 um 20.08.25.png|Leave-One-Out Cross Validation uses all but one point for Training.. ..and uses the one remaining point for Testing. and then iterates until every single point has been used for Testing.|800]]
# k-Fold Cross Validation
> [!Info] Info
> For reliable results, **k-fold Cross-Validation** may run multiple times. After validation, the entire dataset can be used for training.
## 3-Fold Cross Validation
**Concept:** The dataset is split into 3 equal groups. Each group is used as a testing set once, while the remaining two groups are used for training.
**Use Case:** Effective for smaller datasets with limited computational resources.

**Advantages**
- Ensures all data points are used for both training and testing.
- Computationally efficient compared to higher fold counts.

**Disadvantages**
- Less detailed error estimation compared to 10-Fold or LOOCV.

![[IMG_F3DDB174EF93-1.jpg|For example, we could use 3-Fold Cross Validation to compare the errors from the black line to the errors from the green squiggle. Gentle Reminder: These are the original 3 groups. Group 1 Group 3 Group 2 12 Training 13 Testing Total Green Squiggle Error Total Black Line Error vS. In this case, all 3 iterations of the 3-Fold Cross Validation show that the black line does a better job making predictions than the green squiggle. Iteration #1 Again, because each iteration uses a different combination of data for Training... Iteration #2 ...each iteration results in a slightly different fitted line and fitted squiggle. Groups 2 and 3 Group 1 VS. Groups 1 and 3 Group 2 + Iteration #3 VS. Groups 1 and 2 Group 3|800]]
## 10-Fold Cross Validation
**Concept**: Splits the data into 10 equal blocks. Each block is used once as a testing set, with the remaining nine blocks used for training.
**Use Case:** Commonly used for medium to large datasets for robust evaluations.

**Advantages**
- Balances bias and variance in error estimation.
- More reliable than 3-Fold for larger datasets.

**Disadvantages**
- Slightly more computationally expensive than 3-Fold.

![[Bildschirmfoto 2024-12-25 um 21.31.15.png|Imagine that this gray column represents many rows of data. To perform 10-Fold Cross Validation, we first randomize the order of the data and divide the randomized data into 10 equal-sized blocks. Then, we iterate so that each block is used for Testing. 1 2 3 4 5 6 7 8 9 -... 10 1 2 3 4 5 6 7 8 9 10 Then, we Train using the first 9 blocks.. and Test using the tenth block. 4 5 6 7 8 9 2 1|800]]
# Fixed Data Splits
**Concept:** The dataset is split into two parts: a training set (typically 80%) and a testing set (usually 20%). The model is first trained on the training set and then tested on the testing set to evaluate accuracy.
**Use Case:** Effective for large datasets where computational efficiency is important.

**Advantages**
- Simple and fast to implement.
- Suitable for large datasets where more complex validation methods might be computationally expensive.

**Disadvantages**
- The split might not fully represent the diversity of the dataset, leading to potential biases.
- Does not utilize all data points for training and testing simultaneously.

![[fixedatatspits.png]]
**Problem**
Evaluating the performance of a machine learning model requires a **reliable metric** that summarizes how well the model is making predictions on a **classification task**. The challenge lies in **choosing the right performance metric** for the given problem.

**Solution**
The **Confusion Matrix** is a widely used tool for assessing model performance, particularly for **binary classification problems**. It provides a clear summary of the **true positives, false positives, true negatives, and false negatives**, which are critical for calculating various performance metrics.

precison indicate how many predicated labels are coreect
recall increases when learnin rate increased
prcison alwya at laest as largeas recall
precison and recall add up to 1
# Confusion Matrix
> [!WARNING] Labels
> There's no standard for how a Confusion Matrix is oriented. So always read the labels to interpret it.

![[IMG_FB1739CE6568-1.png|When the actual and predicted values are both YES, then we call that a True Positive... ...when the actual value is YES, but the predicted value is NO, then we call that a False Negative... Predicted   Yes No Actual Yes True Positives False Negatives  No  False Positives True Negatives ...and when the actual value is NO, but the predicted value is YES, then we call that a False Positive. ...when the actual and predicted values are both NO, • then we call that a True Negative...]]

![[IMG_6766BD84B7DB-1.jpeg|When there are only two possible outcomes, like Yes and No... Chest Pain Good Blood Circ. Blocked Arteries Weight Heart Disease No No No 125 No Yes Yes Yes 180 Yes Yes Yes No 210 No    ... •.. When there are 3 possible outcomes, like in this dataset that has 3 choices for favorite movie, Troll 2, Gore Police, and Cool as Ice... Jurassic Park III Run for Your Wife Out Kold Howard the Duck Favorite Movie Yes No Yes Yes Troll 2 No No Yes No Gore Police No Yes Yes Yes Cool as Ice ...  ... ...   Predicted   Troll 2 Gore Police Cool As Ice Actual Troll 2 142 22  Gore Police 29 110  Cool as Ice    ...then the corresponding Confusion Matrix has 2 rows and 2 columns: one each for Yes and No.  Predicted   Has Heart Disease Does Not Have Heart Disease Actual Has Heart Disease 142 22 Does Not Have Heart Disease 29 110 ...then the corresponding Confusion Matrix has 3 rows and 3 columns. 寸 In general, the size of the matrix corresponds to the number of classifications we want to predict. Bam. 1401]]
## Sensitivity / Recall / True Positive Rate
![[IMG_C9C9EDDFB488-1 1.png|When we want to quantify how well an algorithm (like Naive Bayes) correctly classifies the actua/ Positives, in this case, the known people with Heart Disease, we calculate Sensitivity, which is the percentage of the actual Positives that were correctly classified. True Positives Sensitivity = True Positives + False Negatives For example, using the Heart Disease data and Confusion Matrix, the Sensitivity for Naive Bayes is 0.83... Naive Bayes Actual Yes No Predicted Yes No FN Actual Yes No TP Sensitivity = = 142 = 0.83 TP + FN 142 + 29 ..which means that 83% of the people with Heart Disease were correctly classified. BAM!!! Predicted Yes 142 22 No 29]]
## Specificity
> [!INFO] Info
> Specificity = 1 - False Positive Rate

![[IMG_463642CAA8B3-1.jpeg|When we want to quantify how well an algorithm (like Logistic Regression) correctly classifies the actual Negatives, in this case, the known people without Heart Disease, we calculate Specificity, which is the percentage of the actual Negatives that were correctly classified. Logistic Regression Actual Yes No Predicted Yes 139 20 No 32 112 True Negatives Specificity = True Negatives + False Positives For example, using the Heart Disease data and Confusion Matrix, the Specificity for Logistic Regression is 0.85... Actual Yes No Predicted Yes No TP FP TN TN Specificity = = 115 TN + FP 115 + 207 - = 0.85 ...which means that 85% of the people without Heart Disease were correctly classified. DOUBLE BAM!!! Now let's talk about Precision and Recall.]]
## Precision
![[IMG_6E036FB42746-1 1.jpeg|Precision = Precision is another metric that can summarize a Confusion Matrix. It tells us the percentage of the predicted Positive results (so, both True and False Positives) that were correctly classified True Positives True Positives + False Positives Actual Yes No False Positive-• Yes TP FP No FN TN Negative For example, using the Heart Disease data and Confusion Matrix, the Precision for Naive Bayes is 0.87... Naive Bayes Actual Yes No True * Negative Predicted Yes No 142 29 22 110 Actual Yes No Predicted Yes TP FP Vo FN TP 142 Sensitivity = - = 0.87 TP + FP 142 + 22 ...which means that of the 164 people that we predicted to have Heart Disease, 87% actually have it. In other words, Precision gives us a sense of the quality of the positive results. When we have high Precision, we have high-quality positive results.]]
## False Positive Rate
> [!INFO] Info
> False Positive Rate = 1 - Specificity

![[IMG_A6C978D10666-1 1.png|The False Positive Rate tells you the percentage of actual Negatives that were incorrectly classified. In this case, it's the known people without Heart Disease who were incorrectly classified. False Positives False Positive Rate = False Positives + True Negatives Actual Yes No Predicted Yes TP FP No FN TN]]
## F-Score
A metric that combines **precision** and **recall** into a single value to evaluate model performance for a fixed threshold $\tau$.

ture flasse mse can only tke vlsue betwewen 0 and1
mse is suitable for regeession problmes
data splitmore trianing then test
validationa dn test data are tyicall disjoijtn

lgosiitc regression can explicity be solved with normla equation
logisitc reg ses gimoid funciton
logsiit is less snetiive to outliers than linear eregression
logisitic regression is used for regression problems

recall is always in the intercall 0 <= recall <= 1
acuarry indi

fscore mean of precision and recall
goal is to maximaize f1score
more trianign saples trianign scor erease
precison recall curve repsrent classifier perofmanc eacross trsholds



![[Pasted image 20250109221117.png]]
### F1-Score
The harmonic mean of precision and recall, giving equal importance to both.

$F_1 = 2 \cdot \frac{\text{precision} \cdot \text{recall}}{\text{precision} + \text{recall}}$
### F$𝛽$-Score
A generalized version of the F1-Score that allows adjusting the importance of **precision** vs **recall** through $\beta$.

$F_\beta = (1 + \beta^2) \cdot \frac{\text{precision} \cdot \text{recall}}{\beta^2 \cdot \text{precision} + \text{recall}}$

**Interpretation**
 $\beta > 1$: Recall is prioritized (e.g., when false negatives are costlier).
$\beta < 1$: Precision is prioritized (e.g., when false positives are costlier).
## Balancing Precision and Recall
**High Cost of False Positives:** Focus on increasing **precision** (e.g., fraud detection, spam email detection, face recognition).
**High Cost of False Negatives:** Focus on increasing **recall** (e.g., intrusion detection).

![[Pasted image 20250109200928.png]]
# Receiver Operating Characteristic (ROC)
![[IMG_575AF10BC09E-1.png]]

![[IMG_0786FDD0CE04-1.jpeg]]

![[IMG_5AEAE80C193D-1.jpeg]]
# Area Under each Curve (AUC)
![[IMG_C01A6F9206A8-1.jpeg]]
# Precision Recall Graph
![[IMG_E9836AA04305-1.jpeg]]

![[IMG_D815E7D161DF-1.jpeg]]
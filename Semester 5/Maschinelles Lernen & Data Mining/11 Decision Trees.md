**Problem**
Traditional models struggle with mixed data types and non-linear relationships.

**Solution**
Decision trees split data iteratively based on feature values, effectively handling mixed types and capturing complex relationships for accurate predictions.

> [!Info] White-Box Algorithm
> A **decision tree** is a **white-box algorithm**, meaning its decision-making process is transparent and easily interpretable. You can trace the decisions from root to leaf to understand how predictions are made.

![[IMG_DECA9E9FB306-1.png|The very top of the tree is called the Root Node or just the Root. This is called an Internal Node or just a Node. Loves Soda Yes No Age < 12.5 Does Not Love Troll 2 Yes No The arrows are called Branches. In this example, the Branches are labeled with Yes or No, but usually it's assumed that if a statement in a Node is True, you go to the Left, and if it's False, you go to the Right. Does Not Love Troll 2 Loves Troll 2 These are called Leaf Nodes or just Leaves.|600]]
# Classification Tree
Used for predicting categorical outcomes by splitting data into groups based on feature values, resulting in decision paths that classify data into distinct categories.

![[The StatQuest Illustrated Guide to Machine Learning 3.jpeg|Given this Training Dataset, we want to build a Classification Tree that uses Loves Popcorn, Loves Soda, and Age. 2 The first thing we do is decide whether Loves Popcorn, Loves Soda, or Age should be the question we ask at the very top of the tree. ??? Loves Popcorn Loves Soda Age Loves Troll 2 Yes Yes 7 No Yes No 12 No No Yes 18 Yes No Yes 35 Yes Yes Yes 38 Yes Yes No 50 No No No 83 No ...to predict whether or not someone will love Troll 2 3 To make that decision, we'll start by looking at how well Loves Popcorn predicts whether or not someone loves Troll 2... Loves Popcorn Yes Loves Troll 2 Yes No No Loves Troll 2 Yes No ...by making a super simple tree that only asks if someone loves Popcorn and running the data down it. For example, the first person in the Training Data loves Popcorn, so they go to the Leaf on the left... Loves Popcorn Lov S Age Loves Troll 2 Yes es 7 No Loves Popcorn Y Yes No Loves Troll 2 Yes No 1 Loves Yes ..and because they do not love Troll 2, we'll put a 1 under the word No. 2 No|800]]

![[The StatQuest Illustrated Guide to Machine Learning 4.jpeg|The second person also loves Popcorn, so they also go to the Leaf in the left, and because they do not love Troll 2, we increase No to 2. The third person does not love Popcorn, so they go to the Leaf on the right, but they love Troll 2, so we put a 1 under the word Yes. Loves Popcorn Loves Soda ge Loves Troll 2 Yes Yes  No Yes NO  No No No Yes Yes 18 35 Yes Yes Yes Yes 38 Yes Yes No 50 No No No 83 No Loves Popcorn Yes Loves Troll 2 Yes No 2 No Loves Troll 2 Yes No 1 Then we do the same thing for Loves Soda. Pogcorn Yes Yes No Loves Soda Yes No Yes Age 12 18 Loves Troll 2 No No Yes Likewise, we run the remaining rows down the tree, keeping track of whether or not each person loves Troll 2 or not. Loves Popcorn BAM!!! Yes No Loves Troll 2 Yes No 1 3 Loves Troll 2 Yes No 2 1 Loves Soda Yes Loves Troll 2 Yes No 3 1 No Loves Troll 2 Yes No 3|800]]
## Impure
> [!TIP] Formula
> $p_{i,k} = \frac{1}{M_i} \sum_{y \in Q_i} I(y = k)$
> 
> $p_{i,k}$: Proportion of class $k$ in node $Q_i$
> $M_i$: Total samples in node $Q_i$
> $Q_i$: Samples in node $i$
> $I(y = k)$: Equals 1 if sample $y$ belongs to class $k$, else 0
> 
> **Interpretation**
> 0 impurity: All samples belong to one class.
> High impurity: Samples are evenly distributed across classes.

![[The StatQuest Illustrated Guide to Machine Learning 5.jpeg|Now, looking at the two little trees, one for Loves Popcorn and one for Loves Soda... Loves Popcorn Yes Loves Troll 2 Yes No 1 3 No Loves Troll 2 Yes No 2 1 10 ...we see that these three Leaves contain mixtures of people who love and do not love Troll 2. TERMINOLOGY ALERT!! Leaves that contain mixtures of classifications are called Impure. Because both Leaves in the Loves Popcorn tree are Impure... ...and only one Leaf in the Loves Soda tree is Impure... In contrast, this Leaf only contains people who do not love Troll 2. Loves Soda Yes Loves Troll 2 Yes No 3 1 No Loves Troll 2 Yes No 3 ...it seems like Loves Soda does a better job classifying who loves and does not love Troll 2, but it would be nice if we could quantify the differences between Loves Popcorn and Loves Soda. 11 The good news is that there are several ways to quantify the Impurity of Leaves and Trees. In theory, all of the methods give similar results, so we'll focus on Gini Impurity since it's very popular and I think it's the most straightforward. One of the most popular methods is called Gini Impurity, but there are also fancy-sounding methods like Entropy and Information Gain. Loves Popcorn Yes Loves Troll 2 Yes No 1 3 No Loves Troll 2 Yes No 2 1 We'll start by calculating the Gini Impurity to quantify the Impurity in the Leaves for loves Popcorn.|800]]
## Gini Impurity
> [!TIP] Formula
> $G(Q_i) = 1 - \sum_{k=1}^{K} p_{i,k}^2$
> 
> $G(Q_i)$: Gini impurity of node $Q_i$, measuring the diversity of classes in the node
> $K$: Total number of classes
> $p_{i,k}$: Proportion of samples in $Q_i$ belonging to class $k$
> 
> **Interpretation**
> Range: $[0, 0.5]$ for binary classification, $[0, 1 - \frac{1}{K}]$ for multi-class
> $G(Q_i) = 0$: Pure node (all samples belong to one class)
> $G(Q_i) > 0$: Higher impurity

![[The StatQuest Illustrated Guide to Machine Learning 6.jpeg|12 To calculate the Gini Impurity for Loves Popcorn, first we calculate the Gini Impurity for each individual Leaf. So, let's start by plugging the numbers from the left Leaf into the equation for Gini Impurity. Loves Popcorn Yes Loves Troll 2 Yes No 1 3 No Loves Troll 2 Yes No 13 Gini for a Leaf Impurity = 1 - (the probability of "yes")2 - (the probability of "no")2 14 For the Leaf on the left, when we plug the numbers, Yes = 1, No = 3, and Total = 1 + 3, into the equation for Gini Impurity, we get 0.375 = 1 - The number for Yes \The total for the Leaf/ 2 2 The number for No The total for the Leaf) 2 = 1 - = 0.375 1 + 3 1 + 3 15 For the Leaf on the right, we get 0.444. Loves Popcorn Yes Loves Troll 2 Yes No 3 No Loves Troll 2 Yes No 2 1 Gini Impurity = 1 - (the probability of "yes")2 - (the probability of "no")2 for a Leaf = 1- 2 2+1 2 = 0.444 2 + 1|800]]

![[The StatQuest Illustrated Guide to Machine Learning 7.jpeg|16 Now, because the Leaf on the left has 4 people in it... ...and the Leaf on the right only has 3, the Leaves do not represent the same number of people. Loves Popcorn Yes No Loves Troll 2 Yes No - 3 Loves Troll 2 Yes No 2 1 Gini Impurity = 0.375 Gini Impurity = 0.444 So, to compensate for the differences in the number of people in each Leaf, the total Gini Impurity for Loves Popcorn is the Weighted Average of the two Leaf Impurities. 17) Total Gini = weighted average of Gini Impurities for the Leaves • Impurity (18 The weight for the left Leaf is the total number of people in the Leaf, 4. Total Gini Impurity 3 = 0.375 + 0.444 = 0.405 4 + 3 4 + 3 and when we do the math, we get 0.405. BAM!!! divided by the total number of people in both Leaves, 7. ...then we multiply that weight by its associated Gini Impurity, 0.375. Now we add to that the weight for the right Leaf, the total number of people in the Leaf, 3, divided by to the total in both Leaves, 7... multiplied by the associated Gini Impurity, 0.444.|800]]
## Entropy
> [!TIP] Formula
> $H(Q_i) = - \sum_{k=1}^{K} p_{i,k} \log_2 p_{i,k}$
> 
> $H(Q_i)$: Entropy of the node $Q_i$, measuring the uncertainty or impurity of the classes in the node
> $K$: Total number of classes
> $p_{i,k}$**:** Proportion of samples in $Q_i$ belonging to class $k$
> 
> **Interpretation**
> Range: $[0, \log_2(K)]$
> $H(Q_i) = 0$: Pure node (all samples belong to one class).
> $H(Q_i)$ increases as class distribution becomes uniform.

 ![[Pasted image 20250109214409.png|800]]
## Numeric Data
![[The StatQuest Illustrated Guide to Machine Learning 8.jpeg|19 Now that we've calculated the Gini Impurity for Loves Popcorn, 0.405. Gini Impurity for = 0.405 Loves Popcorn ...we can follow the same steps to calculate the Gini Impurity for Loves Soda, 0.214. Gini Impurity for = 0.214 Loves Soda 21 Now we need to calculate the Gini Impurity for Age. " Loves Popcorn Loves Soda Age Loves Troll 2 Yes Yes 7 No Yes No 12 No No Yes 18 Yes No Yes 35 Yes Yes Yes 38 Yes Yes No 50 No No No 83 No Loves Popcorn Yes No 20 Loves Troll 2 Yes No 1 3 Loves Troll 2 Yes No 2 1 Loves Soda Yes No The lower Gini Impurity for Loves Soda, 0.214, confirms what we suspected earlier, that Loves Soda does a better job classifying people who love and do not love Troll 2. However, now that we've quantified the difference, we no longer have to rely on intuition. Loves Troll 2 Yes No 3 1 Loves Troll 2 Yes No 3 Bam! However, because Age contains numeric data, and not just Yes/No values, calculating the Gini Impurity is a little more involved. 22 The next thing we do is calculate the average Age for all adjacent rows. Normally, the first thing we do is sort the rows by Age, from lowest to highest, but in this case, the data were already sorted, so we can skip this step. Age  Loves Troll 2 5 7  No 9 12 15  No 18 26.5  Yes 35 36.5  Yes 38 44  Yes 50 66.5  No 83  No|800]]

![[The StatQuest Illustrated Guide to Machine Learning 9.jpeg|23 Lastly, we calculate the Gini Impurity values for each average Age. For example, the first average Age is 9.5, so we use 9.5 as the threshold for splitting the rows into 2 leaves... Age < 9.5 Yes No Loves Troll 2 Yes No 1 Loves Troll 2 Yes No 3 3 .and when we do the math, we get 0.429. Age  Loves Troll 2 7 9.5  No 12  No 15 18  Yes 26.5 35  Yes 36.5 44 38  Yes 50 66.5 83  No No Total Gini Impurity 0.0 + 1 + 6 1+6) 0.5 = 0.429 24 9 5 15 26.5 36.5 44 66.5 Ultimately, we end up with a Gini Impurity for each potential threshold for Age.. Age 7 12 18 35 38 50 83 Loves Troll 2 No No Yes Yes Yes No Gini Impurity = 0.429 Gini Impurity = 0.343 • Gini Impurity = 0.476 Gini Impurity = 0.476 *> Gini Impurity = 0.343 " Gini Impurity = 0.429 No ..and then we identify the thresholds with the lowest Impurities, and because the candidate thresholds 15 and 44 are tied for the lowest Impurity, 0.343, we can pick either one for the Root. In this case, we'll pick 15. BAM!!! Age < 15 Yes Loves Troll 2 Yes No 2 No Loves Troll 2 Yes No 3 2|800]]
## Node Structure
![[The StatQuest Illustrated Guide to Machine Learning 10.jpeg|25 Now remember: our first goal was to determine whether we should ask about Loves Popcorn, Loves Soda, or Age at the very top of the tree.. ??? 26 ...so we calculated the Gini Impurities for each feature... Gini Impurity for Loves Popcorn = 0.405 Loves Popcorn Yes Loves Troll 2 Yes No 1 3 No Loves Troll 2 Yes No 2 1 Loves Soda - Gini Impurity = 0.214 for Loves Soda Yes Loves Troll 2 Yes No 3 1 No Loves Troll 2 Yes No 3 27 ...and because Loves Soda has the lowest Gini Impurity, we'll put it at the top of the tree. Age < 15 Loves Soda Gini Impurity = 0.343 for Age < 15 Yes Loves Troll 2 Yes No 0 2 No Loves Troll 2 Yes No 3 2 BAM!!!|800]]

![[The StatQuest Illustrated Guide to Machine Learning 11.jpeg|28 With Loves Soda at the top of the tree, the 4 people who love Soda, including 3 who love Troll 2 and 1 who does not, go to the Node on the left... 29 Loves Popcorn Loves Soda Age Loves Troll 2 Loves Soda Yes No Yes Yes No es 2 No No Yes Yes Yes Yes 18 Loves Troll 2 Yes No 3 1 Loves Troll 2 Yes No 0 3 35 38 Yes Yes Yes es 50 83 No No 30 Now, because the Node on the left is Impure, we can split the 4 people in it based on Loves Popcorn or Age and calculate the Gini Impurities. 31 When we split the 4 people who love Soda based on whether or not they love Popcorn, the Gini Impurity is 0.25. However, when we split the 4 people based on Age < 12.5, the Gini Impurity is 0. Loves Popcorn Age < 12.5 Yes No Yes No Loves Troll 2 Yes No 1 1 Loves Troll 2 Yes No 2 0 Loves Troll 2 Yes No 0 1 Loves Troll 2 Yes No 3 Gini Impurity = 0.25 Gini Impurity = 0.0 and the 3 people who do not love Soda, all of whom do not love Troll 2, go to the Node on the right. Loves Popcorn Loves Soda Age Loves Troll 2 Yes Yes No No Yes 18 No Yes 351 Yes Yes 38 No 50 No No Loves Popcorn Loves Soda Age Yes Yes 7 12.5 2 No No Yes Yes 26.5 Yes 36.5 Yes 18 35 38 Yes No No 50 No 83 No No Yes Yes Yes No No Loves Troll 2 No Yes Yes Yes No No|800]]

![[The StatQuest Illustrated Guide to Machine Learning 12.jpeg|32 Now remember, earlier we put Loves Soda in the Root because splitting every person in the Training Data based on whether or not they love Soda gave us the lowest Gini Impurity. So, the 4 people who love Soda went to the left Node... Loves Soda Yes No Loves Troll 2 Yes No 3 1 Loves Troll 2 Yes No 0 3 33 ...and the 3 people who do not love Soda, all of whom do not love Troll 2, went to the Node on the right. Now, because everyone in this Node does not love Troll 2, it becomes a Leaf, because there's no point in splitting the people up into smaller groups. Loves Popcorn Loves Soda Age Loves Troll 2 Yes Yes 7 No No 2 No Yes 18 No Yes Yes Yes 35 38 Yes Yes Yes es No 50 No No 83 No 34 In contrast, because the 4 people who love Soda are a mixture of people who do and do not love Troll 2, we build simple trees with them based on Loves Popcorn and Age... Loves Popcorn Age < 12.5 Yes No Yes No Loves Troll 2 Yes No 1 1 Loves Troll 2 Yes No 2 0 Loves Troll 2 Yes No 0 1 Loves Troll 2 Yes No 3 0 Gini Impurity = 0.25 Gini Impurity = 0.0 35 ...and because Age < 12.5 resulted in the lowest Gini Impurity, 0, we add it to the tree. And the new Nodes are Leaves because neither is Impure. Loves Soda Age < 12.5 Loves Troll 2 Yes No 1 Loves Troll 2 Yes No 3 0 Loves Troll 2 Yes No 197|800]]

![[The StatQuest Illustrated Guide to Machine Learning 13.jpeg|36 At this point, we've created a Tree from the Training Data. Now the only thing remaining is to assign output values for each Leaf. Loves Soda Generally speaking, the output of a Leaf is whatever category that has the most counts Loves Popcorn Loves Soda Age Loves Troll 2 Yes Yes 7 No Yes No 12 No No Yes 18 Yes No Yes 35 Yes Yes Yes 38 Yes Yes No 50 No No No 83 No 37 Age < 12.5 Loves Troll 2 Yes No 0 1 Hooray!!! After assigning output values to each Leaf, we've finally finished building a Classification Tree. BAM? Loves Troll 2 Yes No 3 0 Yes Age < 12.5 Not yet, there are still a few things we need to talk about. Loves Troll 2 Yes No 0 3 In other words, because the majority of the people in this Leaf do not love Troll 2, its output value is does not love Troll 2. Yes Does Not Love Troll 2 Loves Soda No Loves Troll 2 No Does Not Love Troll 2|800]]
## Limit Tree Growth
![[IMG_D7E7DF61C5BB-1.jpeg|38 When we built this tree, only one person in the Training Data made it to this Leaf... ...and because so few people in the Training Data made it to that Leaf, it's hard to have confidence that the tree will do a great job making predictions with future data. Loves Soda Loves Popcorn Loves Soda Age Loves Troll 2 Yes Yes  No Yes No 12 No No No Yes Yes 18 35 Yes Yes Yes Yes 38 Yes Yes No 50 No No No 83 No Loves Troll 2 Yes No Age < 12.5 Loves Troll 2 Yes No Loves Troll 2 Yes No However, in practice, there are two main ways to deal with this type of problem. 39 One method is called Pruning, but we'll save that topic for The StatQuest Illustrated Guide to Tree-Based Machine Learning!!! 40 Alternatively, we can put limits on how trees grow, for example, by requiring 3 or more people per Leaf. If we did that with our Training Data, we would end up with this tree, and this Leaf would be Impure.. ...but we would also have a better sense of the accuracy of our prediction because we know that only 75% of the people in the Leaf love Troll 2. NOTE: When we build a tree, we don't know in advance if it's better to require 3 people per Leaf or some other number, so we try a bunch, use Cross Validation, and pick the number that works best. Loves Soda Yes No Loves Troll 2 Yes No 3 1 Loves Troll 2 Yes No 0 3 ALSO NOTE: Even though this Leaf is Impure, it still needs an output value, and because most of the people in this Leaf love Troll 2, that will be the output value. Loves Soda Yes No Loves Troll 2 Does Not Love Troll 2 BAM!!! Now let's summarize how to build a Classification Tree.|800]]
# Regression Tree
Used for predicting continuous outcomes by partitioning data into segments and assigning an average value of the target variable within each segment.

![[IMG_CBF9777B8AD4-1.jpeg|Given these Training Data, we want to build a Regression Tree that uses Drug Dose to predict Drug Effectiveness. 100 Drug 75 Effectiveness % 50 25- 2 Just like for Classification Trees, the first thing we do for a Regression Tree is decide what goes in the Root. ??? 3 10 20 Drug Dose 30 40 To make that decision, we calculate the average of the first 2 Doses, which is 3 and corresponds to this dotted line... ..and then we build a very simple tree that splits the measurements into 2 groups based on whether or not the Dose < 3. Dose < 3 100 Drug 75 Effectiveness % 50 25' 10 20 Drug Dose 30 40 Yes Average = 0 Because only one point has a Dose < 3, and its average Effectiveness is 0, we put 0 in the Leaf on the left. No Average = 38.8 All other points have a Dose ≥ 3, and their average Effectiveness is 38.8, so we put 38.3 in the Leaf on the right. 100 75 50 25 CCCO 10 20 Drug Dose 30 40|800]]

![[IMG_84BDD629C2B1-1.jpeg|5 For the one point with Dose < 3, which has Effectiveness = 0... the Regression Tree makes a pretty good prediction, 0. 100 Drug 75 Effectiveness % 50 25 Dose < 3 Yes No Average = 0 38.8 10 20 Drug Dose 30 40 In contrast, for this specific point, which has Dose > 3 and 100% Effectiveness.. ...the tree predicts that the Effectiveness will be 38.8, which is a pretty bad prediction. 100 75 50 25 Dose < 3 Yes No Average = 0 Average = 38.8 10 20 Drug Dose 30 40|800]]
## Sum of Squared Residuals (SSR)
![[IMG_84BDD629C2B1-1 Kopie.jpeg|100 75- 50 25 We can visualize how good or bad the Regression Tree is at making predictions by drawing the Residuals, the differences between the Observed and Predicted values. We can also quantity how good or bad the predictions are by calculating the Sum of the Squared Residuals (SSR).. ...and when the threshold for the tree is Dose < 3, then the SSR = 27,468.5. 10 20 Drug Dose 30 40 (0 - 0)2 + (0 - 38.8)2 + (0 - 38.8)2 + (0 - 38.8)2 + (5 - 38.8)2 + (20 - 38.8)2 + (100 - 38.8)2 + (100 - 38.8)2 + . + (0 - 38.8)2 = 27,468.5 30,000 15,000 SSR Lastly, we can compare the SSR for different thresholds by plotting them on this graph, which has Dose on the x-axis and SSR on the y-axis. 10 20 Dose 30 40|800]]

![[IMG_CE34B29D56CC-1.png|Now we shift the Dose threshold to be the average of the second and third measurements in the graph, 5. 100 Drug 75 Effectiveness % 50 25- 10 20 Drug Dose 30 10 Now we calculate and plot the SSR for the new threshold, Dose < 5... 30,000 15,000 SSR 40 100 ..and we build this super simple tree with Dose < 5 at the Root. Drug 75- Effectiveness % 50 25- Dose < 5 Yes No Average = 0 Average = 41.1 Because the average Effectiveness for the 2 points with Dose < 5 is 0, we put 0 in the Leaf on the left. All of the other points have Dose ≥ 5, and their average is 41.1, so we put 41.1 in the Leaf on the right. (11 Then we shift the threshold to be the average of the third and fourth measurements, 7... 100 Drug 75- Effectiveness % 50 25- 10 20 Drug Dose 30 40 10 20 Dose 30 40 ...and we see that the SSR for Dose < 5 is less than the SSR for Dose < 3, and since we're trying to minimize the SSR, Dose < 5 is a better threshold. 10 20 Drug Dose 30 40 ...and that gives us this tree. Dose < 7 Yes No Average = 0 Average = 43.7 30,000 15,000 SSR ...and this point on the graph. 10 20 Dose 30 40 121|800]]

![[IMG_8DD596689DD3-1.jpeg|100 75 50 25 12 Then we just keep shifting the threshold to the average of every pair of consecutive Doses, create the tree, then calculate and plot the SSR. Dose < 9 Average = 0 Average = 47 30,000 15,000 SSR 110 20 Drug Dose 30 40 10 20 Dose 14 Then, after shifting the Dose threshold 7 more times, the SSR graph looks like this. Dose < 26 Average = 17 30 100 75 50 25 Average = 30,000 15,000 SSR 10 20 Drug Dose 30 40 10 20 Dose 30 13 After shifting the Dose threshold over 2 more steps, the SSR graph looks like this. 100 75 50 25 Dose < 14.5 Average = 4 Average = 52 30,000 15,000 SSR 10 20 30 40 Drug Dose And finally, after shifting the Dose threshold all the way to the last pair of Doses.. 15 100 75- 50 25 10 20 30 Dose ...the SSR graph looks like this. Dose < 36 Average = 39 Average = 0 30,000 15,000 SSR 10 20 Drug Dose 30 "40 10 BAM! 20 Dose 30 40|800]]

![[IMG_118F8FE6C8AF-1.png|(16 Looking at the SSRs for each Dose threshold, we see that Dose < 14.5 had the smallest SSR... ...so Dose < 14.5 will be the Root of the tree... Dose < 14.5 30,000 15,000-SSR ...which corresponds to splitting the measurements into two groups based on whether or not the Dose < 14.5. 100 75- 50 25 7 10 20 Dose 30 40 Now, because the threshold in the Root of the tree is Dose < 14.5, these 6 measurements go into the Node on the left Dose < 14.5 18 100 75 50 25 10 20 Drug Dose 30 40 ...and, in theory, we could subdivide these 6 measurements into smaller groups by repeating what we just did, only this time focusing only on these 6 measurements. 100 75 50- 25 10 20 Drug Dose 30 40 In other words, just like before, we can average the first two Doses and use that value, 3, as a cutoff for splitting the 6 measurements with Dose < 14.5 into 2 groups... Dose < 14.5 Dose < 3 Average = 0 Average = 5 300 150- SSR ...then we calculate the SSR for just those 6 measurements and plot it on a graph. 10 20 Drug Dose 30 40 7.25 Dose 14.5|800]]

![[IMG_23EF6D37A132-1.jpeg|19 And after calculating the SSR for each threshold for the 6 measurements with Dose < 14.5, we end up with this graph... 100 300- 75 150 SSR 50 25- 7.25 14.5 Dose 10 20 Drug Dose 30 40 and then we select the threshold that gives us the lowest SSR, Dose < 11.5, for the next Node in the tree. BAM? Dose < 14.5 No. No bam. Dose < 11.5 Average = 1 Average = 20|800]]
## Overfitting
![[IMG_23EF6D37A132-1 Kopie.jpeg|20 Earlier, we said in theory we could subdivide the 6 measurements with Dose < 14.5 into smaller groups... 100 75- 50 25- Dose < 14.5 Dose < 11.5 Average = 1 Average = 20 but when we do, we end up with a single measurement in the Leaf on the right because there is the only one measurement with a Dose between 11.5 and 14.5. 100 75 50 25 10 10 20 30 40 20 30 Drug Dose 40 ...and making a prediction based on a single measurement suggests that the tree is Overfit to the Training Data and may not perform well in the future. The simplest way to prevent this issue is to only split measurements when there are more than some minimum number, which is often 20. However, since we have so little data in this specific example, we'll set the minimum to 7.|800]]

![[IMG_C5AAF4A972D2-1.jpeg|21 Now, because there are only 6 measurements with Dose < 14.5, there are only 6 measurements in the Node on the left.. ..and because we require a minimum of 7 measurements for further subdivision, the Node on the left will be a Leaf... BAM!!! 100 Dose < 14.5 Dose < 14.5 100 75 50 4.2% Effective 25 ..and the output value for the Leaf is the average Effectiveness from the 6 measurements, 4.2%. Drug Effectiveness % 75- 50 25- 10 20 Drug Dose 30 40 10 20 Drug Dose 30 40|800]]
## Node Structure
![[IMG_C5AAF4A972D2-1 Kopie.jpeg|22 Now we need to figure out what to do with the 13 remaining measurements with Doses ≥ 14.5 that go to the Node on the right. 100 Dose < 14.5 75- 4.2% Effective 50- 25- 10 20 Drug Dose 30 40 23 Since we have more than 7 measurements in the Node on the right, we can split them into two groups, and we do this by finding the threshold that gives us the lowest SSR. 100 Dose < 14.5 75- 4.2% Effective Dose ≥ 29 50 25- 10 20 Drug Dose 30 40|800]]

![[IMG_EB9B2E2CBB45-1.jpeg|24 And because there are only 4 measurements with Dose ≥ 29, there are only 4 measurements in this Node.. 100 Drug 75 Effectiveness % 50- 25- % Effective Dose < 14.5 Dose ≥ 29 10 20 Drug Dose 30 40 25 Now, because we have more than 7 measurements with Doses between 14.5 and 29, and thus, more than 7 measurements in this Node... 100 Dose < 14.5 75- 4.2% Effective Dose ≥ 29 50 2.5% Effective 25- 100 75 50 25 10 20 Drug Dose 30 40 ..and since the Node has fewer than 7 measurements, we'll make it a Leaf, and the output will be the average Effectiveness from those 4 measurements, 2.5%. Dose < 14.5 4.2% Effective Dose ≥ 29 2.5% Effective we can split the measurements into two groups by finding the Dose threshold that results in the lowest SSR. Dose < 14.5 4.2% Effective Dose ≥ 29 2.5% Effective Dose ≥ 23.5 10 20 Drug Dose 30 40|800]]

![[IMG_D2D695DA59C3-1.jpeg|26 And since there are fewer than 7 measurements in each of these two groups... 100 Drug Effectiveness % 75- 50 25 Dose < 14.5 4.2% Effective Dose ≥ 29 2.5% Effective ...this will be the last split, because none of the Leaves has more than 7 measurements in them. Now, all we have to do is calculate the output values for the last 2 Leaves. Dose ≥ 23.5 10 20 Drug Dose 30 40 So, we use the average Drug Effectiveness for measurements with Doses between 23.5 and 29, 52.8%, as the output for Leaf on the left... 27 100 Drug 75 Effectiveness % 50 25 Dose < 14.5 4.2% Effective Dose ≥ 29 2.5% Effective Dose ≥ 23.5 52.8% Effective 100% Effective ..and we use the average Drug Effectiveness for observations with Doses between 14.5 and 23.5, 100%, as the output for Leaf on the right. 100 Drug 75 Effectiveness % 50 25 10 20 Drug Dose 30 40 10 20 Drug Dose 30 40|800]]
## Multiple Features
![[IMG_47F63E96E677-1.png|So far, we've built a Regression Tree using a single predictor, Dose, to predict Drug Effectiveness. 100 Drug 75- Effectiveness % 50 25- 2 Now let's talk about how to build a Regression Tree to predict Drug Effectiveness using Dose, Age, and Sex. Dose Drug Effect 10 98 20 0 35 6 5 44 etc... etc... Dose Age Sex Drug Effect 10 25 F 98 20 73 M 0 35 54 F 6 5 12 M 44 etc... etc... etc... etc... NOTE: Just like for Classification Trees, Regression Trees can use any type of variable to make a prediction. However, with Regression Trees, we always try to predict a continuous value. Dose 10 20 35 5 etc 10 20 Drug Dose 30 40 First, we completely ignore Age and Sex and only use Dose to predict Drug Effectiveness Age Sex Drug Effect 25 73 F MI 98 0 54 F 6 12 MI 44 etc... etc.. etc ..and then we select the threshold that gives us the smallest SSR. 100 Drug 75 Effectiveness % 50 25 However, instead of that threshold instantly becoming the Root, it only becomes a candidate for the Root. Dose < 14.5 Yes No Average = 4.2 Average = 51.8 10 20 Drug Dose 30 40|800]]

![[IMG_5DF1C66A90DD-1.jpeg|Then, we ignore Dose and Sex and only use Age to predict Effectiveness... Dose  Age  Sex Drug Effect 10  25  F 98 20  73  M 0 35  54  F 6 5  12  M 44 etc...  etc..  etc... etc Lastly, we ignore Dose and Age and only use Sex to predict Effectiveness... Dose Age Sex Drug Effect 10 25| F 98 20 73 M 0 35 54 F 6 5 12 M 44 etc... etc... etc etc. .and we select the threshold that gives us the smallest SSR ..and that becomes the second candidate for the Root. Age > 50 100 75 50- 25 Yes Average = 3 No Average = 52 20 40 Age 60 80 ..and even though Sex only has one threshold for splitting the data, we still calculate the SSR, just like before... 100 75- 50- 25- Yes Average = 52 ...and that becomes the third candidate for the Root. Sex = F No Average = 40 Female Male|800]]

![[IMG_17FF45EE9F4F-1.png|Now we compare the SSRs for each candidate for the Root... Dose < 14.5 Yes Average = 4.2 No Average = 51.8 SSR = 19,564 Age > 50 Yes Average = 3 No Average = 52 SSR = 12,017 Sex = F Yes Average = 52 No Average = 40 SSR = 20,738 ...and pick the one with the lowest : value... Yes ..and because Age > 50 had the lowest SSR, it becomes the Root of the Regression Tree. Age > 50 Yes No|800]]

![[IMG_3F34DB20DC64-1.png|Now that Age > 50 is the Root, the people in the Training Data who are older than 50 go to the Node on the left.. Dose Age Sex Drug Effect  25  8 20 73 M 0 35 54 F 6  12  44 etc etc etcl etc Age > 50 Yes Yes No Yes (8 Then we grow the tree just like before, except now for each split, we have 3 candidates, Dose, Age, and Sex, and we select whichever gives us the lowest SSR... Age > 50 Yes Age > 65 Yes No 0% 5% NOTE: The final prediction is Drug Effectiveness. No Yes No Yes 0% ...and the people who are ≤ 50 go to the Node on the right. No No Dose Age  Sex Drug Effect 10 25 F 98 20 3    35 54    5 12  M 44 etc etc etc ...until we can no longer subdivide the data any further. At that point, we're done building the Regression Tree. Age > 50 TRIPLE BAM!!! Yes No Age > 65 Sex = F No Yes No 5% 75% 39%|800]]
# CART (Classification and Regression Tree)
- The **CART algorithm** (used in Scikit-learn) trains decision trees by recursively splitting the dataset into **two subsets** (binary tree).
- At each node, the algorithm finds the **best split** based on a **feature** and a **threshold** that minimizes impurity.
- The **CART algorithm** is **greedy**:
	- It finds the **best split** at the **current node**.
	- It does **not look ahead** to evaluate whether the split will minimize impurity in deeper levels of the tree.
	- This greedy approach may result in **suboptimal splits** deeper in the tree.
## Tree Structure
**Scenario:** A flower with a **5 cm petal length** and **1.5 cm petal width** reaches the green node.

**Class Probabilities:**
- Setosa: **0%** (0/54 samples)
- Versicolor: **90.7%** (49/54 samples)
- Virginica: **9.3%** (5/54 samples)

The model predicts **Versicolor** as the most likely class based on the majority class at the green node.

![[Pasted image 20250110151635.png|600]]



**Leaf Node**
- **Definition:** A node with no child nodes.
- **Function:** Once a leaf node is reached, the majority class at that node is outputted as the prediction.  

**Split Node
- **Definition:** A node that asks a question (condition) to decide which path to follow next.
- **Function:** It continues the decision process by splitting into child nodes based on the condition.

**Samples Attribute of the Node**
- **Definition:** The number of training samples that reach the node.
- **Example:**
	- **Root Node:** Contains all training samples (150).
	- **Left Child Node:** 50 samples belong to the class “setosa.”
	- **Right Child Node:** The remaining 100 samples continue further down the tree. 

**Gini Attribute of the Node**
- **Definition:** Measures the **Gini Impurity**, which indicates how mixed the classes are at a node.
- **Interpretation:**
	- **Pure Node (Gini = 0):** All samples belong to the same class (e.g., the orange node).
	- **Max Impure Node (Gini ≈ 0.667):** Classes are equally distributed (e.g., the root node).

**Value Attribute of the Node**
- **Definition:** Shows the number of samples belonging to each class at that node (used to estimate class probabilities).
## Step-by-Step
**1. Splitting Dataset into Left & Right Subsets**
The dataset at each node is split into **two subsets** based on a **feature** and a **threshold** using the following formula:

$Q^{left}_i(\theta) = \{(x, y) \mid x_n \leq t_i\} \quad \text{and} \quad Q^{right}_i(\theta) = Q_i \setminus Q^{left}_i(\theta)$

Explanation:
- $Q_i$: Dataset at node $i$.
- $x_n$: Value of feature n for a sample.
- $t_i$: Threshold used to split the data.
- $Q^{left}_i(\theta)$: Subset of samples where the feature value $x_n \leq t_i.$
- $Q^{right}_i(\theta)$: Remaining samples that go to the right child node.

**2. How Does CART Choose the Best Split?**
At each node $i$, the algorithm tries to find the **best split** by evaluating multiple candidate splits. A candidate split is defined as:

$\theta = (n, t_i)$

Explanation:
- $n$ is the feature to split on.
- $t_i$ is the threshold value.

The algorithm sorts all unique values of feature $n$ and calculates the **midpoints** between adjacent values. Each midpoint is considered as a potential threshold $t_i$.

**3. Evaluating the Quality of a Split (Cost Function)**
The **cost function** used to evaluate the quality of a split is calculated as the **weighted average of the impurity** of the left and right child nodes:

$J(Q_i, \theta) = \frac{M^{left}_i}{M_i} G(Q^{left}_i(\theta)) + \frac{M^{right}_i}{M_i} G(Q^{right}_i(\theta))$

Explanation:
- $J(Q_i, \theta)$: Cost function for a split at node $i$ with split parameters $\theta$.
- $M_i$: Total number of samples at node $i$.
- $M^{left}_i$  and  $M^{right}_i$: Number of samples in the left and right child nodes, respectively.
- $G(Q)$: Impurity measure (e.g., **Gini Impurity** or **Entropy**) for a subset $Q$.

Interpretation:
- The **cost function** calculates the **weighted impurity** of the left and right subsets.
- The split with the **lowest cost function** is selected as the best split.

**4. Recursive Splitting Process**
After the best split is selected:
1. The data is divided into **left** and **right** subsets based on the chosen feature and threshold.
2. The same process is repeated **recursively** for each child node until:
	- The **maximum depth** is reached.
	- The node becomes **pure** (contains samples from only one class).
# Regularization
Prone to **overfitting** because they make very few assumptions about the data. The model adapts too closely to the training data, capturing noise instead of underlying patterns.
## Pre-Pruning
Pre-pruning sets constraints to stop the tree from growing too complex during training.

**Min-Sample Pruning**
- Nodes are only split if they contain at least **k samples**.
- Prevents the creation of splits that are too specific and irrelevant.

**Max-Depth Pruning**
- Limits the **maximum depth** of the tree.
- Ensures the tree doesn’t grow too deep, reducing the risk of overfitting by preventing overly specific splits.
## Post-Pruning
Post-pruning involves growing the full tree first and then pruning it back using validation data to simplify the model.

**Validation-Based Pruning**
- After the tree is fully grown, **validation data** is used to decide whether certain leaves (nodes) are reasonable.
- If a leaf doesn’t contribute significantly to reducing the error, it is pruned (removed).
- This process improves the model’s generalization to new, unseen data.
# Random Forest
Instead of relying on a single model, Random Forests **combine predictions** from multiple models (trees) to get more robust and accurate results.

**How it works**
1. Bootstrapping
	- Random subsets of the training data are created through **bootstrapping** (sampling with replacement).
	- Each Decision Tree in the forest is trained on a different **bootstrap sample**.
2. Random Feature Selection
	- For each potential split in a tree, only a random subset of features is considered.
	- This introduces **diversity** among the trees and reduces correlation between them.
3. Prediction Aggregation
	- Predictions from individual trees are aggregated to produce the final output:
		- **Classification:** Use **voting** (hard or soft)
		- **Regression:** Use **averaging**

![[Pasted image 20250110144805.png|600]]
## Voting Methods
![[Pasted image 20250110144536.png|600]]

**Hard Voting**
- Each tree votes for a class, and the majority class is the final prediction.

**Soft Voting**
- Each tree provides a probability for each class.
- The class with the highest **average probability** is selected as the final prediction.
## Hyperparameters
Can be tuned using **RandomizedSearchCV** to find the optimal hyperparameters.

```python
from sklearn.model_selection import RandomizedSearchCV as RSCV

param_grid = {
    'n_estimators': np.arange(8, 16, 32, 64, 100, 200, 500),
    'max_features': np.arange(0.1, 0.3, 0.7),
    'max_depth': [3, 5, 7, 9],
    'max_samples': [0.3, 0.5, 0.8]
}

model = RSCV(RandomForestClassifier(), param_grid, n_iter=15).fit(X_train, y_train)
model = model.best_estimator_
```

**Number of Trees**
- Typical values: **100-500** trees.
- More trees generally improve accuracy but increase computation time.

**Sample Size**
- Fraction of samples used to train each tree.
- Typical range: **20%-100%** of the dataset.

**Number of Features per Node**
- Default: **√N** (square root of the number of total features).
- Helps to reduce correlation between trees.

**Maximum Depth**
- Defines how deep each tree can grow.
- Full depth is allowed by default, but setting a limit (e.g., **3-7**) can reduce overfitting.
## Out-of-Bag (OOB) Error
- **Out-of-Bag samples** refer to the data points that were **not used** in the bootstrap sample for training a particular tree.
- The **OOB error** is the proportion of these samples that are misclassified by the model.

![[Pasted image 20250110145142.png|400]]

**How to calculate OOB error**
1. Use each OOB sample to test the trees that didn’t see it during training.
2. Aggregate their predictions.
3. Calculate the percentage of incorrect predictions.

```python
from sklearn.ensemble import RandomForestClassifier

model = RandomForestClassifier(n_estimators=100, oob_score=True)
model.fit(X, y)
print(model.oob_score_)  # Prints the OOB score for this fit
```


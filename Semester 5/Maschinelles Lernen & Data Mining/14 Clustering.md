A method in **unsupervised learning** that involves grouping a set of objects such that objects in the same group (called a **cluster**) are more similar to each other than to objects in other groups.

In **unsupervised learning**, the training data does **not have any target values**. We are only given input features, and the goal is to **model the underlying distribution** of the data to **discover hidden patterns**.

**Goals**
- Identify the **structure** of the data.
- **Group similar objects** together.
- **Discover patterns** that might not be apparent in labeled data.

**Example**
![[Pasted image 20250110193650.png|600]]

Given **16 data points** with features **height** and **weight**, we can cluster them into different groups:
- **2 clusters**: Broad grouping.
- **5 clusters**: More granular grouping.

The objective is to **separate the data into distinct clusters** based on similarity.
# Clustering Types
## Hard Clustering
- Each data point is **assigned to exactly one cluster**.
- Example: A customer belongs to either **Cluster A** or **Cluster B**, not both.
## Soft Clustering
- Each data point is assigned a **probability of belonging to a cluster**.
- Example: A customer has a **70% probability** of belonging to **Cluster A** and a **30% probability** of belonging to **Cluster B**.
# K-Means
Popular clustering method that partitions the data into **K clusters** by minimizing the **distance** between data points and their cluster centroids.

![[Pasted image 20250110194321.png|800]]

**Steps**
1. Randomly initialize **K centroids** (means).
2. Assign each data point to the **nearest centroid**.
3. Calculate the new centroid for each cluster.
4. Repeat steps 2 and 3 until the centroids **no longer move significantly** or a **stop criterion** is met.
## K-Means++
An improved version of K-Means that **chooses initial centroids more intelligently** to improve convergence.

![[Pasted image 20250110194355.png|400]]

**Steps**
1. **Randomly select** the first centroid from the data points.
2. For each remaining data point, calculate the **distance** to the nearest previously chosen centroid.
3. Select the next centroid with a probability proportional to the squared distance.
4. Repeat until **K centroids** are chosen.
## Stop-Criterion
- **Stop when** the coordinates of the centroids change very little from one iteration to the next.
- **Stop after** a fixed number of iterations (e.g., 50 iterations).
- **Stop after** a set amount of time (e.g., 1 minute).
## Quality-Metric
The **quality** of K-Means clustering is measured by the **within-cluster inertia** (also called the **potential function**) which calculates the **sum of squared distances** between each data point and its **closest centroid**.

$\Phi(C, X) = \sum_{m=1}^{M} \min_{c \in C} \left(d\left(x^{(m)}, c\right)^2\right)$

**Where**
- $M$: Total number of data points
- $x^{(m)}$: Data point m
- $C$: Set of cluster centroids
- $d\left(x^{(m)}, c\right)$: Distance between data point $x^{(m)}$ and centroid $c$

**Explanation**
- The formula calculates the **sum of squared distances** from each data point to its **closest centroid**.
- **K-Means seeks to minimize this function**, meaning it aims to **reduce the distance between data points and their respective centroids** as much as possible.
## Number of Clusters
### Elbow Method
- Run K-Means with **different values of K**.
- Plot the **sum of squared errors (SSE)** for each value of K.
- The optimal K is the **“elbow point”** where the SSE starts to level off.

![[Pasted image 20250110195603.png|400]]
### Silhouette Score
> [!INFO] Runtime Complexity
> The runtime complexity of the K-Means algorithm is:
> 
> $O(L \cdot K \cdot N \cdot M)$
> 
> With
> $L$: Number of iterations  
> $K$: Number of clusters  
> $N$: Number of data points (samples)  
> $M$: Number of features (dimensions)  

Measures the **quality of a clustering result** by calculating how similar a point is to its own cluster compared to other clusters.

$s_m = \frac{b_m - a_m}{\max(a_m, b_m)}$

**Where**
- **$a_m$**: Average distance of point $x_m$ to all other points in the same cluster.
- **$b_m$**: Average distance of point $x_m$ to points in the nearest other cluster.

**Interpretation**
- $s_m$ close to 1: The point is well-clustered.
- $s_m$ close to 0: The point is near the boundary between clusters.
- $s_m$ close to -1: The point is likely in the wrong cluster.

![[Pasted image 20250110195920.png|400]]

![[Pasted image 20250110200612.png|600]]

![[Pasted image 20250110200901.png|600]]
# DBSCAN
> [!INFO] Runtime Complexity
> $O(M^2)$ in the worst case.
> With efficient indexing: $O(M * log M)$ for non-degenerate data.

A **density-based clustering algorithm** that groups points into clusters based on **density** and can **identify noise points** (outliers).

**Key Parameters**
- $minPts$: The minimum number of points required to form a dense region (cluster).
- $ε$ (epsilon): The distance threshold used to define the neighborhood of a point.

**Key Concepts**
- **Core Point**: A point with at least $minPts$ neighbors within a distance of $ε$. (e.g. Point A)
- **Border Point**: A point that is **reachable** from a **core point** but has fewer than $minPts$ neighbors. (e.g. Point B, C)
- **Noise Point**: A point that is **neither a core point nor a border point**. (e.g. Point N)

![[Pasted image 20250110204315.png|300]]

**Reachability Condition**
Point $x$ is reachable from point $y$ if the distance between them is less than $ε$.

**Algorithm Steps**
1. Select an unprocessed point P.
2. If P is not a core point (less than $minPts$ within range $ε$), classify P as noise and go back to step 1.
3. If P is a core point, form a new cluster:
	- Assign all neighbors of P to the cluster.
	- Repeat for all newly assigned core points.
4. Repeat the process until all points are processed.

**Advantages**
- No need to specify the number of clusters in advance.
- Can find arbitrarily shaped clusters.
- Can detect noise points (outliers).

**Disadvantages**
- Struggles with datasets that have large differences in density between clusters.

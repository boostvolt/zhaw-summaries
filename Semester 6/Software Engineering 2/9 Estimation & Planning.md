# Key Terms & Concepts
## Story Points
- A unit of measure for expressing the **overall size** of a user story, feature, or other piece of work.
- They represent an amalgamation of the effort involved, complexity, risk, etc.. There's no set formula for defining this size.
- **Relative Values**: The raw point values are unimportant; what matters are the _relative_ values. A 2-point story should be twice as much as a 1-point story and two-thirds of a 3-point story.
- **Getting Started**: One approach is to pick a very small story and call it 1 point. Another is to pick a medium-sized story and assign it a mid-range value (e.g., 5 if using a 1-10 range). Subsequent stories are estimated by comparison.
- **Dealing with Uncertainty**: For loosely defined stories, make assumptions, guess, and move on.
## Velocity
- A measure of a team's rate of progress per iteration.
- Calculated by summing the story points of user stories _completed_ by the team during an iteration. (If estimating in ideal time, velocity is the sum of ideal time estimates completed.)
- **Forecasting**: A team's past velocity is the best guess for their future velocity (e.g., if they completed 10 points last iteration, they'll likely complete 10 this iteration).
- **Corrects Estimation Errors**: Because velocity is an observed measure, it self-corrects for initial over/underestimation of the overall project size. If a project is 200 points and initial velocity is thought to be 25 points/iteration (8 iterations), but observed velocity is only 20, the projection correctly changes to 10 iterations without re-estimating stories.
## Relative Estimation
- The core principle behind story points. Teams estimate the size of work items relative to each other, rather than in absolute units like hours initially.
- The restaurant analogy illustrates this: ordering a "large" soda is a relative size choice without knowing the exact ounces, based on experience and comparison to "small" or "medium".
## Techniques for Estimating
- **Effort vs. Accuracy**: More effort in estimating doesn't always yield proportionally better accuracy; there are diminishing returns. Agile teams aim for "good enough" estimates with less effort. No estimate is ever perfect.
- **Collaborative Estimation**: Estimates are best derived collaboratively by the entire team who will do the work, not by a single expert. This is because anyone might work on anything, and others can provide valuable input or catch underestimations.
### The Estimation Scale
- Humans are best at estimating things within one order of magnitude.
- Nonlinear scales like Fibonacci (1, 2, 3, 5, 8) or powers of two (1, 2, 4, 8) are recommended. These reflect greater uncertainty with larger items.
- Numbers are like "buckets" for items of similar size.
- Using 0 can be useful for trivial items but requires understanding that multiple 0-point stories don't sum to 0 effort overall.
- For larger items (epics/themes), the scale can extend (e.g., 13, 20, 40, 100). Avoid false precision like estimating 66 vs. 67 for large items
### Common Estimation Techniques
- **Expert Opinion**: An expert provides an estimate based on intuition or experience. It's quick but less useful for agile stories requiring diverse skills.
- **Analogy**: Compare the story being estimated with one or more already-estimated stories. We are better at relative size estimation. Use **triangulation**: compare against a couple of other stories (e.g., bigger than a 3, smaller than an 8, so it's a 5).
- **Disaggregation**: Splitting a large story into smaller, easier-to-estimate pieces. Be careful not to disaggregate too far, as this can lead to forgetting pieces or inaccurate sums (sum of parts error).
## Planning Poker
- An agile estimation technique combining expert opinion, analogy, and disaggregation, resulting in quick, reliable, and enjoyable estimation.
- **Participants**: All developers (programmers, testers, DBAs, analysts, UI designers, etc.). Typically not exceeding ten people. The Product Owner participates to clarify stories but does not estimate.
- **Process**:
    1. Each estimator receives a deck of cards with valid estimates (e.g., 0, 1, 2, 3, 5, 8, 13, 20, 40, 100).
    2. A moderator (often PO or analyst) reads the story description.
    3. PO answers clarifying questions from estimators. Goal is a valuable estimate cheaply, not exhaustive analysis.
    4. Estimators privately select a card representing their estimate.
    5. All cards are revealed simultaneously.
    6. If estimates differ, high and low estimators explain their reasoning. This is for learning, not attacking.
    7. After discussion (e.g., using a 2-minute timer to keep it brief ), estimators re-estimate by selecting a card again.
    8. Repeat until estimates converge (usually within 2-3 rounds). Exact agreement isn't strictly necessary if outliers are okay with the consensus.
- **Why it works**: Leverages multiple expert opinions, encourages justification of estimates (improving accuracy, especially with uncertainty/missing info ), leads to averaging of sorts, and is engaging.
- **When to Play**: For initial backlog estimation (may take a few sessions) and for ongoing estimation of new stories (e.g., short meeting near end of each iteration).
## Conditions of Satisfaction
- The criteria defining project success or failure, crucial for release planning.
- Often tied to financial outcomes (money saved or generated).
- For most projects, these are defined by a combination of **schedule, scope, and resource goals** brought by the Product Owner. One factor is usually preeminent (e.g., date-driven vs. feature-driven project).
## Level of Planning
- Planning occurs at multiple levels: Strategy, Portfolio, Product, **Release**, **Iteration**, **Day**.
- Agile teams primarily focus on the innermost three (Release, Iteration, Day) or four (including Product) levels.
- In Scrum, this maps to: Product Backlog (Product/Release planning), Sprint Backlog (Iteration planning), and Daily Scrum (Day planning).
## Prioritization
- The Product Owner is responsible for prioritizing, considering advice from the development team, especially on sequencing.
- Key factors include desirability (financial value, Kano model), cost, amount of learning/new knowledge created, and amount of risk removed.
## Re-Estimating
- Story points are estimates of overall size/complexity, not time.
- Re-estimate only when the team believes a story's _relative size_ has changed compared to other stories, not just because it took longer/shorter than initially thought in hours. Velocity handles discrepancies between estimates and actual time.
# Planning for Value
Involves prioritizing features by considering:

1. The financial value of having the features.
2. The cost of developing (and perhaps supporting) the new features.
3. The amount and significance of learning and new knowledge created.
4. The amount of risk removed.
## Financial Value
- Prioritize based on business value – how much money the organization will make or save.
- Sources of revenue can be new, incremental, or retained revenue, and operational efficiencies.
- Consider the time value of money using concepts like Net Present Value (NPV) and Internal Rate of Return (IRR, also ROI).
## Cost
- A critical factor in determining overall priority; many features seem great until their cost is known.
- Cost can change over time.
- It's useful to do a rough conversion of story points or ideal days into monetary cost for perspective.
## New Knowledge
- Projects often involve significant effort in acquiring new knowledge (about the product - "what," or the project - "how").
- This effort is fundamental, as initial knowledge is rarely complete.
- Acquiring knowledge helps reduce uncertainty.
## Risk
- A risk is anything that has not yet happened but might, and that would jeopardize or limit the project's success.
- Common types include schedule risk, cost risk, and functionality risk.
- **Risk-Value Prioritization**: Features can be plotted on a risk-value matrix to guide prioritization:
    - High Risk / High Value: Do first (to mitigate risk early while aiming for high value).
    - Low Risk / High Value: Do second.
    - Low Risk / Low Value: Do last.
    - High Risk / Low Value: Avoid if possible.
## Kano Model of Customer Satisfaction
- A model developed by Noriaki Kano to categorize product features based on their impact on customer satisfaction, aiding in prioritization.
- **Dynamic Nature**: Features migrate down the model over time (e.g., wireless internet in hotels was an exciter, became linear, now largely a must-have).
- **Assessing Features**: Survey 20-30 users by asking two questions for each feature (functional form: "How would you feel if the feature IS present?" and dysfunctional form: "How would you feel if the feature IS NOT present?"). Answers use a 5-point scale (e.g., I like it, I expect it, I am neutral, I can live with it, I dislike it). Cross-referencing responses categorizes the feature (Must-have, Linear, Exciter, Indifferent, Reverse, Questionable).
- **Relative Weighting (Karl Wiegers)**: An alternative using expert judgment instead of questionnaires. Collaboratively assess each feature's relative benefit (1-9 if implemented) and relative penalty (1-9 if not implemented). Calculate Total Value (Benefit + Penalty, possibly weighted), % Value, % Cost (from story point estimate), and then Priority (Value % / Cost %). Higher priority for features with a better value-to-cost ratio. It's important to consider the penalty of absence.
### Feature Categories
- **Threshold (Must-have/Basic Attributes)**: Features that are expected and taken for granted. Their absence leads to dissatisfaction, but their presence (beyond a basic level) doesn't significantly increase satisfaction. Example: a bed in a hotel room.
- **Linear (Performance)**: Features where "more is better." Customer satisfaction is directly and linearly correlated with the quantity or quality of these features. Example: larger hotel room, more comfortable bed.
- **Exciters and Delighters**: Unexpected features that provide great satisfaction if present, but their absence does not cause dissatisfaction as customers don't expect them (often "unknown needs"). Example: TV built into a treadmill.
### Prioritization
- Include all Must-have features (partial implementation may be adequate as satisfaction gains drop off).
- Maximize Linear features, as they directly increase satisfaction.
- Include some Exciters/Delighters if time permits.
# Planning Levels
## Planning Onion
- **Strategy** (highest level, long-term organizational goals)
- **Portfolio** (managing groups of products or projects)
- **Product** (vision and roadmap for a specific product)
- **Release** (planning for a specific upcoming release, typically 3-9 months )
- **Iteration / Sprint** (planning for a short cycle, 1-4 weeks )
- **Day** (daily coordination and planning)
- Agile teams typically focus their planning efforts on the Product, Release, Iteration, and Day levels. In Scrum, this corresponds to Product Backlog management, Release Planning, Sprint Planning, and the Daily Scrum.
## Release Planning
- **Purpose**: Creates a high-level plan for a period longer than an iteration (e.g., 3-6 months or 3-12 iterations), deciding how much can be developed and when a releasable product might be ready. It conveys expectations and provides context for iterations.
- **Content**: The release plan is usually a list of user stories for the project. It does _not_ detail which developers work on which tasks or the sequence within an iteration; these are deferred to iteration planning. It's often good to assign work to the first 1-3 iterations and treat the rest as a larger bucket.
- **Tools**: Using physical cards or sticky notes is effective for manipulating stories during planning if collocated.
- **Updating**: The release plan is a living document and should be revisited and updated regularly (e.g., after each iteration or every 4-6 weeks).
- **Responsibilities**: The **Product Owner** defines conditions of satisfaction, prioritizes features, and makes scope decisions. The **development team** estimates stories, forecasts velocity, and collaborates on the feasibility of the plan

**Process:**
1. Determine **Conditions of Satisfaction** (project goals for schedule, scope, resources).
2. **Estimate User Stories** (in story points or ideal days). Only necessary for stories with a reasonable chance of inclusion in the upcoming release.
3. Select an **Iteration Length** (typically 2-4 weeks). Factors include release length, uncertainty, feedback ease, priority stability, overhead, and maintaining urgency.
4. Estimate **Velocity** (team's rate of progress per iteration). Use past velocity if available and relevant; techniques exist for forecasting if not.
5. **Prioritize User Stories** (Product Owner's responsibility, with team input, based on value, cost, risk, learning).
6. **Select Stories and a Release Date**:
    - For **feature-driven** projects: Sum estimates of needed features / expected velocity = number of iterations needed 
    - For **date-driven** projects: Number of iterations (from calendar) * expected velocity = total story points that fit in the release.
7. **Iterate**: Adjust scope, date, or resources if initial plan doesn't meet conditions of satisfaction.
## Iteration Planning
- **Purpose**: Creates a detailed plan for a single iteration (horizon of 1-4 weeks).
- **Process**: User stories from the release plan selected for the current iteration are decomposed into smaller tasks. These tasks are then estimated, typically in ideal hours.
- **Responsibilities**: This is a team-based activity. **Developers** (the entire team performing the work) break down stories into tasks, estimate the tasks, and make a collective commitment to the amount of work they can complete during the iteration. The Product Owner clarifies stories and defines priorities.

**Commitment-Driven Iteration Planning**:
1. Identify an iteration goal.
2. The team selects a high-priority story.
3. The story is expanded into tasks, and tasks are estimated.
4. The team asks itself if they can commit to completing that story (and any previously committed stories).
5. If yes and capacity remains, select another story. If yes and capacity is full, iteration planning is done. If no, the story is removed (or broken down/re-negotiated), and the process may repeat or conclude.
# Relationship & Origins
## Agile
The term "Agile software development" was coined in 2001 with the **Agile Manifesto**. Seventeen software thought leaders met to define better ways of developing software, resulting in a set of values and principles. It emerged from challenges in software development.
## Lean
This is the Western term for the **Toyota Production System (TPS)**, an approach to manufacturing that proved highly successful for Toyota. The underlying principles of TPS, known as the Toyota Way, are applicable in many domains, including software development. Lean arose from manufacturing.
## Compatibility
Lean and Agile are considered two sets of highly compatible values and principles for successful product development. More and more organizations combine these principles to cover the entire chain from product concept to delivery.
## Methodologies / Process Tools
Scrum, XP (Extreme Programming), and Kanban are concrete ways (often called agile methodologies or process tools) to put Lean and Agile principles into practice. They are seen as three slightly overlapping flavors of Lean and Agile software development. These techniques are process tools, and like any tool, using the right one helps but doesn't guarantee success. All three, for instance, recommend using physical task boards.
## Kanban Method Origin
The Kanban Method was created to manage and improve professional service businesses and to offer a humane approach to change. While its roots are in Lean Manufacturing, it has been adapted specifically for knowledge work, which involves intangible and virtual goods and services.
# Lean Software Development
Lean Software Development applies lean management principles to the creation of software.

**Definition of "Lean"**: The core idea is to reduce waste in a system and produce higher value for the final customer. This involves elimination of waste to create process speed and improve efficiency and quality by minimizing time, capital, and cost, all driven by a philosophy of continuous improvement.
## 7 Principles
- **Eliminate Waste**: Spend time only on what adds real customer value.
- **Amplify Learning**: When faced with tough problems, increase feedback.
- **Decide as Late as Possible**: Evaluate options but delay final decisions until they can be based on facts rather than speculation.
- **Deliver as Fast as Possible**: Provide value to customers as soon as they ask for it or as soon as it's ready.
- **Empower the Team**: Allow those who directly add value to utilize their full potential and make relevant decisions.
- **Build Integrity In**: Integrity (quality, fitness for purpose) should be an integral part of the product and process from the beginning, not an afterthought.
- **See the Whole**: Beware of optimizing individual parts of a system if it negatively impacts the overall system's performance or value delivery.
## Types of Waste
Any activity that consumes resources but brings no value to the end customer.
### Waste in Code Development
- Partially completed work (can become outdated). Solution: Iterative cycle with modular code.
- Defects (necessitate correction and retesting). Solution: Maintain an up-to-date test suite and incorporate customer feedback.
### Waste in Project Management
- Extra processes (e.g., wasteful or unnecessary documentation). Solution: Documentation review.
- Code Handoffs (knowledge loss between teams/individuals). Solution: Don't handoff code; use cross-functional teams.
- Extra Functions (features not desired or needed by the customer). Solution: Engage in continuous interaction with the customer.
### Waste in Workforce Potential
- Task Switching (multi-tasking reduces effectiveness due to context switching). Solution: Focus on a limited number of tasks per release or timeframe.
- Waiting (for instructions, information, decisions, or dependencies). Solution: Empower developers to make decisions and provide necessary access to information.
## Kaizen
- A Japanese word meaning "change for the better" or continuous improvement. "Kai" means change, and "Zen" means good.
- It involves making small, incremental changes, typically initiated by the person performing the work, using their common sense and intuition. This is a core element of the Toyota Way philosophy.
# Kanban Method
Kanban (Japanese for "visual card," "signboard," or "billboard") is a method for defining, managing, and improving services that deliver knowledge work.

**Method vs. Methodology/Framework**: Kanban is a **management method or approach**, not a prescriptive methodology or an incomplete framework. It is applied _to an existing process_ or way of working to help manage work better and improve service delivery, rather than replacing what is already in place.
## Values
- **Transparency**: Sharing information openly improves the flow of business value.
- **Balance**: Different aspects, viewpoints, and capabilities must be balanced for effectiveness.
- **Collaboration**: Working together is central; Kanban aims to improve how people work together.
- **Customer Focus**: Every Kanban system aims to deliver value to customers.
- **Flow**: Work is viewed as a flow of value; seeing this flow is essential.
- **Leadership**: Needed at all levels to achieve value delivery and improvement.
- **Understanding**: Self-knowledge (individual and organizational) is foundational for improvement.
- **Agreement**: Commitment to move towards goals together, respecting different opinions.
- **Respect**: Valuing, understanding, and showing consideration for people.
## Principles
### Change Management Principles
- **Start with what you do now**: Understand current processes as actually practiced, respecting existing roles, responsibilities & job titles.
- **Agree to pursue improvement through evolutionary change**: Kanban employs an evolutionary change approach, building on existing ways of working and seeking to improve them via feedback and collaboration.
- **Encourage acts of leadership at all levels**: Small observations and improvement suggestions by individuals, regardless of formal roles, are key drivers of change.
### Service Delivery Principles
- Understand and focus on customer needs and expectations.
- Manage the work; let people self-organize around it.
- Regularly review the network of services and its policies to improve outcomes.
## Practices
- **Visualize (the Workflow)**: Make work and its flow visible (e.g., on a Kanban board), including risks. This improves transparency and collaboration.
- **Limit Work in Progress (WIP)**: "Stop starting, start finishing!". WIP is the number of work items currently being worked on. Limiting WIP helps balance utilization with ensuring a smooth flow of work and reduces context switching.
- **Manage Flow**: Flow is the movement of work. The goal is to complete work smoothly and predictably at a sustainable pace. Monitoring flow with data helps manage expectations and identify improvements.
- **Make Policies Explicit**: Define and make visible all agreements on how work is handled. This includes pull criteria (Definition of Done for a step), WIP limits, Classes of Service, meeting schedules, etc.. Policies should be sparse, simple, well-defined, visible, always applied, and readily changeable by those providing the service. They should enable self-organization.
- **Implement Feedback Loops**: Establish regular feedback mechanisms (e.g., boards, metrics, meetings/cadences) to coordinate delivery and improve the service.
- **Improve Collaboratively, Evolve Experimentally**: Use the scientific method (Observe, Hypothesis, Experiment, Collect data, Analyze, Repeat) for hypothesis-driven, safe-to-fail experiments to make continuous, collaborative changes.
## Elements
### Visualize the Workflow (Kanban Board)
- A visual display (physical or electronic) of work items (represented as cards or tickets ) and their progression through a defined workflow.
- Columns represent workflow activities/steps; work items are pulled from left (options/new work) to right (value delivered to customers). Horizontal lanes can represent different work types, projects, or classes of service to distribute capacity.
- It models the _actual current_ workflow ("Start where you are now" ) rather than an idealized one. Each Kanban system and board are unique.
- WIP limits are typically displayed on the board.
### Limit Work in Progress (WIP) / Pull System
- **WIP (Work in Progress)**: The work items that have entered the system (or a specific part of it) and have not yet exited.
- **Limit WIP / WIP Limit**: An explicit policy that constrains the maximum number of work items allowed in a given part of the Kanban system at any time (e.g., per column, per lane, per person, or for the whole system). Limits prevent starting new work when downstream capacity is full, helping to reduce delays and context switching.
- **Pull System**: A system where work is "pulled" into the next step only when capacity is available in that downstream activity. The availability of capacity (WIP below the limit) acts as a pull signal. This contrasts with "push" systems where work is scheduled without regard to current capacity. The mantra is "Stop starting, start finishing!". WIP limits are key to establishing a pull system.
### Cumulative Flow Diagram (CFD)
- A chart that shows the cumulative number of arrivals and departures of work items from each step (or column) in a workflow over time.
- The different colored bands represent the amount of WIP in each stage of the workflow.
- It visually indicates the stability and characteristics of the workflow, helping to identify bottlenecks, approximate average lead time (horizontal distance between lines), and WIP levels. Parallel lines between steps generally indicate a stable flow where inflow matches outflow.

![[Pasted image 20250527195948.png]]
### Lead Time / Cycle Time
- **Lead Time**: The time it takes for a single work item to pass through the system from a defined start (commitment point) to a defined completion point.
- **Customer Lead Time**: The time between receiving a customer's request and delivering on it.
- **System Lead Time**: The elapsed time for a work item to move from the commitment point to the first column on its Kanban board that has no work in progress limit.
- Kanban aims to make lead time as small and predictable as possible.
- **Lead Time Distribution**: A chart showing the frequency of observed lead times, indicating system predictability.
- **Lead Time Run Chart**: Plots lead times of completed items sequentially over time to observe trends (e.g., are lead times increasing or decreasing?).
- "Cycle time" is often used interchangeably with lead time, especially for specific process segments.
### Classes of Service
- A specific level of service applied to the treatment of a work item established through a defined set of policies. The choice may reflect relative value, risk, or cost of delay.
- Four common archetypes are: Expedite (high urgency, may bypass WIP limits ), Fixed Date (must be done by a specific date ), Standard (normal processing ), and Intangible (impact of delay is unknown ).
### Commitment Point
The point in the workflow where the decision is made to start activities to deliver a work item.
### Options
Ideas, requirements, or customer needs that are considered prior to the commitment point (upstream part of the Kanban system). They are vetted against capacity and urgency, with many often discarded.
### Blockers
Something impeding the flow of a work item. Kanban systems visualize and manage blockers to remove them quickly.
### STATIK (Systems Thinking Approach to Introducing Kanban)
A repeatable, humane method for designing a service-oriented Kanban system. Its iterative steps include:

1. Identify sources of dissatisfaction.
2. Analyze demand (what customers request, types of work, patterns).
3. Analyze system capabilities (how much is delivered, how fast, how predictable).
4. Model the workflow (activities work items go through).
5. Identify classes of service.
6. Design the Kanban system (board, tickets, metrics, cadences, policies). This process should be done collaboratively with a representative group.
### Cadences (Meetings/Reviews)
- Regularly scheduled meetings or reviews that serve as feedback loops for coordination, observation, and improvement of work delivery.
- Examples include Team Kanban Meeting (often daily, "walking the board" from right to left ), Team Retrospective, and (Internal Team) Replenishment Meeting (selecting work to pull next).
- Existing meetings can often be evolved to serve these purposes.
# Scrum vs. Kanban
## Commonalities
- Both are process tools under the Lean and Agile umbrella.
- Both aim for continuous improvement and efficient value delivery.
- Both typically use visual boards to manage and track work.
- Both emphasize empowering teams.
## Key Differences

|Feature|Scrum|Kanban|
|:--|:--|:--|
|**Iterations**|Prescribes fixed-length, timeboxed iterations (Sprints).|Timeboxed iterations optional; focuses on continuous flow.|
|**Commitment**|Team commits to a specific scope of work for the Sprint.|Commitment is typically to finishing items once started; no fixed iteration scope.|
|**Primary Metric**|Velocity (for planning and process improvement).|Lead Time / Cycle Time (for planning and process improvement).|
|**Teams**|Prescribes cross-functional teams.|Allows specialist teams; cross-functional is optional.|
|**Item Size**|Items must be small enough to be completed within one Sprint.|No particular item size is prescribed.|
|**WIP Limits**|WIP is limited indirectly by the amount of work a team forecasts for a Sprint.|WIP is limited directly and explicitly per workflow state (column).|
|**Estimation**|Prescribed.|Optional.|
|**Prescribed Chart**|Burndown chart.|No specific chart prescribed (CFD, Lead Time Distribution charts are common).|
|**Board**|Sprint backlog owned by one team; board often reset between Sprints.|Kanban board can be shared by multiple teams/individuals; board is persistent.|
|**Roles**|Prescribes 3 roles (Product Owner, Scrum Master, Developers).|Does not prescribe any roles.|
|**Backlog**|Prescribes a prioritized product backlog.|Prioritization is optional (though common practice).|
|**Adding Items**|Items cannot be added to an ongoing Sprint once it has started.|New items can be pulled into the system whenever capacity (WIP limit) allows.|
|**Cadence**|Driven by fixed-length Sprints and prescribed meetings.|Flow-based; cadences (meetings) are established as needed to manage flow.|
## Benefits of Kanban Often Observed
- Bottlenecks become clearly visible in real-time, leading to collaboration to optimize the whole value chain.
- Provides a more gradual evolution path from waterfall to agile software development, helping companies that previously have been unable or unwilling to try agile methods.
- Provides a way to do agile software development without necessarily having to use time-boxed fixed-commitment iterations such as Scrum sprints.
- Useful for situations where sprints don't make much sense, such as operations and support teams with a high rate of uncertainty and variability.
- Tends to naturally spread throughout the organization to other departments such as HR and sales, thereby increasing visibility of everything that is going on at the company.
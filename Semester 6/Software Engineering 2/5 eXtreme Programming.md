**Definition**: eXtreme Programming (XP) is an agile software development methodology.
**Goal**: To provide principles and practices to deal with common risks in software development projects.
# Core Values
XP is built upon a set of core values:
## Communication
- Everyone is part of the team, emphasizing daily face-to-face communication.
- Collaboration on all aspects, from requirements to code.
- Working together to create the best possible solution.
## Simplicity
- Do what is needed and asked for, but no more ("You Ain't Gonna Need It" - YAGNI).
- Maximizes value for the investment made.
- Take small, simple steps towards the goal, mitigating failures as they happen.
- Create something to be proud of and maintain it long-term at reasonable costs.
## Feedback
- Deliver working software in every iteration.
- Demonstrate software early and often, listen to feedback, and make necessary changes.
- Adapt the process to the project, not the other way around.
## Courage
- Tell the truth about progress and estimates.
- Plan for success, not documenting excuses for failure.
- No fear, as no one works alone (e.g., pair programming).
- Adapt to changes whenever they happen.
## Respect
- Every team member gives and receives respect.
- Everyone contributes value, even if it's enthusiasm.
- Developers respect customer expertise and vice-versa.
- Management respects the team's right to accept responsibility and authority over their work.
# Basic Principles
XP is guided by several fundamental principles:

**Analogy of Learning to Drive**: Software development should be controlled by making many small adjustments (like driving a car), requiring feedback, opportunities for correction, and reasonable costs for those corrections.
## Fundamental Principles
- Rapid feedback 
- Assume simplicity 
- Incremental change 
- Embracing change 
- Quality work 
## Other Key Principles
- Teach learning 
- Small initial investment 
- Play to win 
- Concrete experiments 
- Open, honest communication 
- Work with people's instincts, not against them 
- Accepted responsibility 
- Local adaptation 
- Travel light 
- Honest measurement 
# Practices
## The Planning Game
- Balances business and technical considerations.
- **Business people decide**: Scope, Priority, Composition of releases, Dates of releases.
- **Technical people decide**: Estimates, Consequences, Process, Detailed Scheduling.
## Small Releases
- Releases should be as small as possible, containing the most valuable business requirements.
- Each release must make sense as a whole (no half-working features).
- Favors frequent small releases (e.g., monthly) over infrequent large ones (e.g., semi-annually).
## Metaphor
- A shared story or "common understanding" of how the system works.
- Establishes a "shared vocabulary" for both technical and non-technical team members.
- Defines basic system elements and their relationships.
## Simple Design
- The right design runs all tests, has no duplicated logic, and has the fewest possible classes and methods.
- "Put in what you need when you need it".
- Design is emergent and grows through refactoring; no big design upfront (BDUF).
## Unit-Testing
- Automated tests are written by developers for the code they produce. This is a cornerstone of ensuring code quality and enabling refactoring. (This complements the TDD practice below).
## Refactoring
- Continuously improve the existing source code to make implementing new features easier.
- Automated tests provide a safety net for refactoring without fear.
## Pair Programming
- All production code is written by two people at one screen, with one keyboard/mouse.
- **Two roles**: One programmer focuses on the current method (driver), the other thinks about broader context, refactoring, etc. (navigator).
- Pairs change frequently.
## Collective Ownership
- Anyone who sees an opportunity to add value to any portion of the code is required to do so at any time.
- Everyone takes responsibility for the whole system.
- Not everyone knows every part equally well, but everyone knows something about every part.
## Continuous Integration
- Code is integrated and tested at least once a day, sometimes more.
- The build process must be automated, typically on a dedicated machine.
- Automated tests are run to identify problems early.
## 40-Hour Week (Sustainable Pace)
- Promotes sustainable development by spreading effort evenly.
- Extended periods of overtime negatively impact productivity.
- Goal: Be fresh every morning, tired and satisfied every evening.
- Stepping back can lead to "Aha!" moments.
## On-Site Customer
- A real customer (user who will use the system) must be physically present with the team to answer questions rapidly.
- The customer doesn't necessarily work 100% of their time on the project but needs to be available.
- The customer also helps with prioritization.
## Coding Standards
- Due to collective ownership and constant refactoring, coding practices must be unified within the team.
## Testing (Test-Driven Development - TDD)
- Any program feature without an automated test simply doesn't exist.
- Tests become part of the system and allow it to accept change.
- **Development cycle**: Listen (requirements) -> Test (write first) -> Code (simplest) -> Design (refactor).
## Slack
- This refers to intentionally building some buffer or unallocated time into iterations or release plans.
- It allows the team to handle unexpected issues, explore new ideas, pay down technical debt, or learn new skills without disrupting the planned flow of feature work.
- Helps maintain a sustainable pace and improve quality.
## Spike
- A spike is a short, time-boxed exploration or experiment to learn about a particular technical or functional area where there's uncertainty.
- It's used to gain knowledge, reduce risk, or make a more informed decision (e.g., choosing a technology, understanding a complex requirement) before committing to a full implementation.
- The output is knowledge, not necessarily production code.
## Incremental Design
- This principle suggests that the system's design should evolve incrementally over time, rather than being fully defined upfront.
- As new features are added or requirements change, the design is refactored and improved to accommodate them while maintaining simplicity and quality.
- It complements "Simple Design" and "Refactoring."
## Self-Organized Team
- The team collectively decides how to best accomplish its work, rather than being directed by a manager on task assignments or technical solutions.
- Team members take responsibility for their commitments and manage their own tasks to meet the iteration goals.
- This promotes ownership, motivation, and adaptability.
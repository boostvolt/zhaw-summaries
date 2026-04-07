# Goals & Purpose
User stories are a central part of agile requirements management, aiming to address several key challenges in software development:

- **Improve Communication**: They primarily address the communication problem between those who want the software (customers, users) and those who will build it (developers).
- **Achieve Balance**: User stories help create a balance in requirements definition, preventing dominance by either the business side (mandating functionality and dates without regard for reality or developer understanding) or the developer side (using technical jargon and losing sight of business needs).
- **Shared Responsibility**: They foster a collaborative approach where resource allocation becomes a shared problem, rather than falling disproportionately on one side. If developers are solely responsible, they might trade quality for features; if the business is solely responsible, lengthy upfront negotiations might occur with features dropped later.
- **Manage Imperfect Schedules**: Acknowledging that software schedules cannot be perfectly predicted and that users develop new ideas as they see the software, user stories support spreading decision-making across the project lifecycle rather than making all decisions upfront.
- **Support Opportunistic and Participatory Design**: Stories facilitate designing solutions by moving opportunistically between top-down and bottom-up approaches and allow users to become part of the design team.
- **Valuable to the User**: They ensure that development focuses on delivering functionality that is valuable to a user or customer, described in their language.
- **Just Enough Detail**: Stories aim to capture just enough information, deferring details to be captured through collaboration "just in time" for development, avoiding the false precision of overly detailed upfront specifications.
- **Facilitate Agile Planning**: User stories are integral to agile processes, appearing in backlogs, sprint planning, and on task boards.

**Focus on Conversation over Written Text:**
- User stories emphasize verbal communication ("Conversation") over extensive written documentation.
- While written notes provide a record, are reviewable, and shareable, relying solely on them can lead to misinterpretations ("You built what I asked for, but it's not what I need.") because words can be imprecise. Written requirements can also be time-consuming to produce and may become outdated.
- Verbal communication allows for instantaneous feedback, clarification, a richer, shared understanding, and can spark new ideas. The text on story cards is less important than the conversations had about them.
# Application
- A user story is a concise, written description of a piece of functionality that will be valuable to a user (or customer) of the software.
- They are a way to express requirements in agile development.
- They fit into an overall agile framework that includes sprints, a product backlog, task boards, and a "Definition of Done".
# Structure
**Common Template**: The most widely recognized format is: **"As a [user role], I want to [goal] so that [benefit]"**.

_Example:_ "As a frequent flyer, I want to rebook a past trip so that I save time booking trips I take often".
## Card
Traditionally, stories are written on physical notecards. These cards can be annotated with estimates, notes, etc.. This represents the written, tangible aspect.
## Conversation
The details behind the story emerge through ongoing conversations between the development team and the product owner (or customer representative). This is where questions are asked (e.g., about refund policies, cancellation rules, confirmation methods) and ambiguities resolved.
## Confirmation
Acceptance tests (or conditions of satisfaction) confirm that the story has been implemented correctly according to the user's expectations. These are often written on the back of the story card and should ideally be automated.

_Example:_ For "As a user, I can cancel a reservation," confirmation criteria could include: "Verify that a premium member can cancel the same day without a fee," "Verify that an email confirmation is sent".
## Adding Details
- Details can be captured as conditions of satisfaction (acceptance tests).
- Alternatively, larger stories can be broken down into smaller, more detailed sub-stories. For instance, "As a user, I can cancel a reservation" might be broken into stories for premium and non-premium members. These approaches are not mutually exclusive and can be combined; by the time it's implemented, each story will have conditions of satisfaction.
## User Roles
- It's important to identify different user roles rather than writing all stories from the perspective of a generic "the user," which can lead to missing stories.
- User roles help define different needs based on how various users use the software, their background, and familiarity.
- Using roles (e.g., "frequent flyer," "repeat traveler") helps in thinking about solving needs for real people and incorporating these roles into the story format.
## Non-functional Requirements
These system-level constraints (e.g., "The system must support Internet Explorer down to version 9") can also be formulated as user stories or incorporated into the "Definition of Done". They affect the design and testing of many other stories
## Knowledge-Acquisition Stories (Spikes)
When a team lacks enough knowledge to estimate or implement a story, a "spike" can be created. This is a time-boxed user story aimed at research or prototyping to "buy knowledge". Example: "As a developer I want to prototype two alternatives for the new filtering engine so that I know which is a better long-term choice".
# Granularity
User stories exist at different levels of granularity, often visualized as an iceberg where the most detailed items are at the top (highest priority) and larger, less defined items are below:
## Epic
An epic is a very large user story that is typically too big to be implemented in a single iteration. It often represents a broad area of functionality.

- Story-writing workshops often generate epics initially.
- Example: "As a product owner, I can manage the product backlog" could be an epic.
## Theme
A theme is a collection of related user stories. Themes group stories that share a common focus or objective.
## User Story
These are smaller, more granular pieces of functionality that can usually be completed within a single iteration. Epics are often broken down into multiple user stories through iteration.

_Example:_ The epic "As a product owner, I can manage the product backlog" might be broken down into stories like "As a product owner, I can add, edit and delete backlog items" and "As a product owner, I can sort the product backlog"
## Process
Development often begins by identifying epics during initial brainstorming or story-writing workshops. These epics are then refined and broken down into smaller, manageable stories as they move up in priority and closer to implementation.
# INVEST
The INVEST acronym stands for:

- **I – Independent**: Stories should be as independent as possible from other stories. This allows them to be developed and tested in any order and makes planning more flexible.
- **N – Negotiable**: A user story is not a rigid contract. It's a placeholder for a conversation, and its details can be negotiated and refined between the customer and the development team. The story should capture the essence, not every detail upfront.
- **V – Valuable**: Every story must deliver clear value to the user or customer. The "so that [benefit]" clause in the standard format helps articulate this value.
- **E – Estimable**: The team should be able to estimate the effort required to implement a story. If a story cannot be estimated, it often indicates it's too large (an epic) or not well understood, requiring further conversation or a spike.
- **S – Small (or Sized Appropriately)**: Stories should be small enough to be completed within an iteration (i.e., be the "right size for planning" ). Large stories (epics) need to be broken down. This aligns with the principle of delivering working software frequently.
- **T – Testable**: A story must be testable to confirm it has been implemented correctly. This means having clear acceptance criteria or conditions of satisfaction (test cases should be written before development ). If a story isn't testable, it's hard to know when it's "done."

Adhering to these INVEST criteria, along with the key agile requirement principles (active user involvement, empowered teams, emerging requirements, 'barely sufficient' detail, small pieces, 80/20 rule, and essential communication/collaboration ), helps ensure that user stories are effective tools for agile planning and development.
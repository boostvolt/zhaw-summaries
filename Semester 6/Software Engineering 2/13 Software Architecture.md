# Software Architecture
Software architecture is fundamentally about the **significant, high-level design choices** that shape a system. It defines the system's core **structure and organization**, which includes:

- Its main software elements or components.
- The **externally visible properties** and interfaces of these elements.
- The **relationships** among these elements, and their connection to the wider environment.
- The key **principles guiding its design and evolution**.

This understanding of architecture exists both as a **conceptual blueprint** (conception in one's mind) and as the **observable characteristics** (perception) of the actual system.
# Software Architect
We see as an essential characteristic of good architects that he (or she) construct the best possible systems under the circumstances and accompany their development. Systems that are understandable, durable, maintainable, functional, performant and secure. Systems that respond robustly to errors and positively amaze their respective stakeholders instead of annoying them. In short: Good architects deliver good quality.

**Key Tasks of an Architect**:
- **Decide**: Make decisions, often under uncertainty, considering architectural tradeoffs.
- **Document**: Create adequate documentation to communicate the architecture. Record rationale.
- **Prove Feasibility**: "One line of working code is worth 500 lines of specification." Try before choosing.
- **Program**: Architects must be hands-on. "If you design it, you should be able to code it." (J. Coplien: Architect always/also implements).
- **Communicate**: "Stand up," "Talk the talk." Communication is king.
- **Negotiate**: With stakeholders, seek the value in requested capabilities.
- **Simplify**: Reduce accidental complexity while managing essential complexity. "Simplicity before generality, use before reuse."
- **Standardize**: Reduce entropy by establishing consistent approaches.
- **Listen**: Hear stakeholder concerns.
- **Observe**: "Don't control, but observe." Get the 1000-foot view.
- **Think (about the future)**: Consider failures, support, maintenance, and that systems become legacy. Future-proofing is not fully possible.
- **Lead**: Give developers autonomy. Architecture is a team effort ("There is no 'I' in architecture").
# Enterprise vs. Application Architecture
**Enterprise Architecture**: "... defines ways how an enterprise uses many applications." The metaphor used is **city planning**. It looks at the broader landscape of how multiple systems interact within an organization to achieve business goals.

**Application Architecture**: "... defines the pieces that compose an application." The metaphor used is **building architecture**. It focuses on the internal design and structure of a single software application, including how it's decomposed into components, layers, packages, and namespaces. It is about the organization of code within that application.
# Difficulties of Software Design
## Complexity
Abstraction helps by simplifying complex software. However, if we omit fundamental characteristics (essential properties) during this simplification, our understanding or representation of the software may no longer be true to the original (losing fidelity)
## Conformity
Software must conform to the complex and varied environments and interfaces of the systems it interacts with.
## Changeability
Software is subject to perpetual change. Because it _can_ be changed easily (in theory), many changes _are_ made, requiring the design to accommodate this.
## Invisibility
Software is intangible and cannot be directly visualized like physical structures. Different views and models are needed to understand its structure and behavior.
# Architectural Drivers
## Non-functional Requirements
These influence the behavior of an application at the overall system level. They are often the "ilities" of a system.

**Other Cross-Cutting Concerns**: Logging, exception handling, audit requirements, regulatory compliance, interoperability.
### Measurable at Runtime
- **Performance** (response time/throughput): System must meet required response times.
- **Security**: Protect against unauthorized access and destruction.
- **Availability**: System must be operational and meet defined minimum uptime.
- **Usability**: System must be usable for its intended purpose.
- **Robustness**: System must run stably and not fail under load.
### Incapable of Direct Measurement at Runtime
- **Scalability**: Ability to handle increased load (scale out or up).
- **Integrability**: Ability to fit seamlessly into an existing environment.
- **Portability**: Ability to support different platforms.
- **Maintainability**: Ease of making changes, clear structure, defined maintenance interfaces.
- **Testability**: Ease of testing the system as a whole and its components; system should support testing.
- **Reusability**: System components can be reused in other systems.
## Principles of Software Design
- These influence the behavior and structure of an application at the module or component level.
- **Modularity**: Components should be easily exchangeable, understandable, and self-contained (e.g., ACL, DB Access, Validator).
- **Portability**: Software designed to run in other environments.
- **Changeability**: System is malleable, making changes easier (e.g., by separating domain specifics from cross-cutting concerns).
- **Conceptual Integrity**: Similar functions in a system should be designed similarly (using industry standards, reference architectures).
- **Intellectual Control**: Design should be understood in detail by those responsible (interface, scope).
- **Buildability**: Design must specify a target system that can be realized by the given team in the given time (considering know-how, technology).
### Coupling and Cohesion
- **Coupling**: The degree of interdependence between software modules. Aim for _low coupling_. Variants include Data, Stamp, Control, Common, and Content Coupling (Content is worst).
- **Cohesion**: The degree to which elements within a module belong together. Aim for _high cohesion_. Variants include Coincidental (worst), Logical, Temporal, Procedural, Communicational, Sequential, and Functional Cohesion (Functional is best, focusing on information hiding).
- _Effect_: High cohesion usually leads to low coupling. This promotes design independence, smaller interfaces, low interface traffic, unity in problem-solving, and better encapsulation.
### Design for Change
- **Domain-Specific Changes**: Foreseeable based on system context (workflow, users).
- **Analytical Changes**: Due to imprecise initial specifications.
- **Downsizing Changes**: Due to budget constraints, leading to omitted functionality.
# Key Terms
## Standard
- A widely adopted technology, protocol, or framework. Often represents a specific implementation choice.
- _Examples:_ .NET, SOA, Java EE. Frameworks like TOGAF, ODP, ISA represent broader enterprise architecture standards/frameworks.
## Style
- A named collection of architectural design decisions that are applicable in a given development context, constrainarchitectural design decisions, and result in beneficial qualities in each resulting system. It's a general approach or philosophy for structuring a system.
- _Examples:_ Independent Components, Call-and-Return, Virtual Machine, Data Flow, Data Centered.
## Pattern
- A proven, reusable solution to a commonly occurring problem within a given context in software design/architecture. Patterns are more specific than styles.
- _Examples:_ Transaction Script, Domain Model, Table Module. Design patterns like those from the GoF book operate at a lower level of detail.
- **Relationship**: The process of mapping requirements to a target system often goes through these three levels of decreasing abstraction: Architecture Standards → Architecture Style → Design Patterns.
## Layer vs. Tier
**Layer**: A logical structuring mechanism for the components that make up a software system. Layers are about separation of concerns and organization of code. A component in one layer usually only communicates with components in adjacent layers.
_Example_: Presentation Layer, Application Layer, Business Service Layer, Business Object Layer, Integration Layer.

![[Pasted image 20250527112611.png]]

**Tier**: A physical structuring mechanism, referring to where different parts of the system are deployed and run. A tier typically represents a separate physical machine or process.
_Example_: A 3-tier architecture often has a Presentation Tier (client/web server), an Application Tier (business logic server), and a Data Tier (database server).

![[Pasted image 20250527112907.png]]

**Relationship**: Layers are logical; tiers are physical. Layers can be deployed on the same tier or distributed across multiple tiers. For example, a 3-layer application could run on a single tier (all on one server) or be distributed across 2 or 3 tiers.
# Architectural Styles
| Architectural Style        | Application Examples                        | Advantage                                     | Disadvantage                                                            |
| :------------------------- | :------------------------------------------ | :-------------------------------------------- | :---------------------------------------------------------------------- |
| **Independent Components** |                                             |                                               |                                                                         |
| Communicating Processes    | Parallel processing                         | Simple modeling, scalability                  | Complexity of individual elements                                       |
| Event Systems              | GUIs, Real-Time Systems                     | Independence of elements, change-friendliness | Non-deterministic behavior of elements                                  |
|                            |                                             |                                               |                                                                         |
| **Call-and-Return**        |                                             |                                               |                                                                         |
| Main Program & Subroutine  | Structured Programming, Client-Server (RPC) | Defined control flow                          | Scalability, expandability (can become complex)                         |
| Object-Oriented            | General design, Client-Server               | Universal applicability                       | Complexity, freedom of application (can lead to overly complex designs) |
| Layered                    | SOA, Multi-Tier Architectures               | Conceptual integrity, locality of changes     | Performance (due to indirection), complexity                            |
|                            |                                             |                                               |                                                                         |
| **Virtual Machine**        |                                             |                                               |                                                                         |
| Interpreter                | Processor and OS simulation                 | Portability, flexibility                      | Performance                                                             |
| Rule-Based Systems         | Expert systems                              | Flexibility through rules                     | Complexity, performance                                                 |
|                            |                                             |                                               |                                                                         |
| **Data Flow**              |                                             |                                               |                                                                         |
| Batch Sequential           | Host Systems                                | Data control                                  | Flexibility, interaction (can be limited)                               |
| Pipes and Filters          | Software Converters, Compilers              | Flexibility, distribution                     | Complexity                                                              |
|                            |                                             |                                               |                                                                         |
| **Data Centered**          |                                             |                                               |                                                                         |
| Repository                 | Master Data Management                      | Simple                                        | Single Point of Failure                                                 |
| Blackboard                 | Data-driven control systems                 | Scalability                                   | Application limited (specific use cases)                                |
# Three Big Patterns
These patterns describe different ways to organize business logic, particularly in relation to data access.
## Transaction Script
- **Description**: Organizes business logic by procedures where each procedure handles a single request from the presentation layer. It's a collection of scripts, each corresponding to a user action or system transaction.
- **Use Cases**: Suitable for applications with simple business logic, where each transaction has its own distinct logic and there's little shared behavior or complex domain rules. Often a good starting point for simple applications.
- **Effort to Enhance**: Initially low effort for simple logic, but effort increases sharply (exponentially) as the complexity of domain logic grows, leading to duplicated code and difficulty in managing changes.
## Domain Model
- **Description**: An object model of the problem domain that includes both behavior (methods) and data (attributes). It aims to represent the rich business logic and rules of the domain through a network of interconnected objects.
- **Use Cases**: Best for complex business logic where there are many rules, relationships, and behaviors that need to be managed. It promotes reusability and maintainability when dealing with intricate domains.
- **Effort to Enhance**: Higher initial effort compared to Transaction Script, but the effort to enhance grows more linearly and slowly as domain logic complexity increases, making it more sustainable for complex systems.
## Table Module
- **Description**: Organizes business logic with a single instance (often a singleton class) that encapsulates the logic for all rows in a database table or view. Each Table Module handles the business logic related to a specific database table.
- **Use Cases**: A middle ground between Transaction Script and Domain Model. Suitable when there's more logic than fits comfortably in Transaction Scripts but a full Domain Model seems like overkill. Good for applications where the logic is centered around tables (e.g., CRUD operations with some business rules).
- **Effort to Enhance**: Effort to enhance is generally between Transaction Script and Domain Model. It can handle moderate complexity better than Transaction Script but may become unwieldy if the domain logic becomes very rich and interconnected across many tables.
# C4 Model
The C4 model (Context, Containers, Components, Code) provides a way to visualize software architecture at different levels of abstraction, making it easier to communicate to various audiences. It emphasizes decomposition.
## System Context Diagram
- **Purpose**: Shows the software system in its environment, interacting with users and other software systems. It's the highest level of abstraction, setting the scene.
- **Answers**: What system are we building? Who uses it? How does it fit into the existing environment?
- **Audience**: Everyone (technical and non-technical).

![[Pasted image 20250527114405.png]]
## Container Diagram
- **Purpose**: Zooms into the system boundary from the Context diagram to show the high-level technical building blocks (containers). A "container" is something deployable and runnable like a web application, mobile app, server-side application, database, file system, microservice, etc.
- **Answers**: What's the overall shape of the software system? What are the high-level technology choices? How are responsibilities distributed? How do containers communicate? Where do developers write code for features?
- **Audience**: Technical people inside and outside the team (developers, architects, operations).

![[Pasted image 20250527114439.png]]
## Component Diagram
- **Purpose**: Decomposes each container further to show the major structural components or modules within it and their interactions. Components are often abstractions behind an interface.
- **Answers**: What components make up each container? Do all components have a home? Is the high-level software design clear?
- **Audience**: Primarily software developers within the team.

![[Pasted image 20250527114638.png]]
## Code
- **Purpose**: Zooms into individual components to show the code-level implementation details (e.g., classes, interfaces, functions, and their relationships). UML class diagrams or similar can be used here.
- **Details**: This level is optional and often generated on-demand from the code by IDEs, as it can be very detailed and change frequently.
- **Audience**: Software developers within the team.

![[Pasted image 20250527114716.png]]
# Architecture Canvas
The Architecture Canvas is a tool for concisely capturing and communicating key architectural aspects, inspired by the Business Model Canvas. It aims for clarity at a glance.

**Purpose**: To provide a quick, high-level overview of a software system's architecture, business drivers, technical choices, and operational aspects. It's useful for discussions, onboarding, and ensuring shared understanding.

## Tech Stack Canva
Focuses on the technologies used. Sections include:

- Business goals
- Sizing numbers (users, data volume)
- Major quality attributes
- Frontend Technologies
- Backend Technologies
- Data Storage & Management
- API & Integrations
- Security & Compliance
- Testing & QA
- Infrastructure & Deployment
- Monitoring & Analytics
- Development Workflow & Collaboration
## Architecture Inception Canvas (arc42)
Helps at the beginning of a project to define the "what" and "how." Sections include:

- Business Case
- Functional Overview
- Business Context (communication partners)
- Organizational Constraints
- Quality Goals (top 3)
- Technical Constraints
- Architectural Hypotheses (important decisions)
- Technical Challenges & Risks
## Architecture Communication Canvas (arc42)
Focuses on communicating the architecture. Divides into "The Problem" and "The Solution." Sections include:

- Value Proposition
- Key Stakeholder
- Business Context
- Core Functions
- Quality Requirements
- Core Decisions (Good or Bad)
- Technologies
- Components/Modules
- Core Risks and Missing Information
## Advantages
- **Conciseness**: Provides a high-level summary on a single "page."
- **Shared Understanding**: Facilitates communication and alignment among stakeholders.
- **Focus**: Helps identify and focus on the most critical aspects.
- **Starting Point**: Can be a good starting point for more detailed documentation or discussions.
## Disadvantages
- **High-Level**: Lacks detailed information necessary for implementation.
- **Potential for Oversimplification**: May not capture all nuances of a complex architecture.
- **Requires Discipline**: Needs to be kept up-to-date to remain useful.


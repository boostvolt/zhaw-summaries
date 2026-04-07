# Cynefin Framework
The Cynefin framework, is a sense-making and decision-making framework that helps leaders and teams understand the type of situation they are facing and adopt appropriate strategies. It's particularly useful in software development for determining when upfront analysis is beneficial versus when an approach emphasizing feedback and adaptation is required.

- **Definition of Cynefin**: "Cynefin" is a Welsh word signifying the multiple, often unperceivable, factors in our environment and experience that influence us.    
- **Definition of Framework**: In this context, Cynefin is a conceptual structure that helps categorize problems and guide responses, rather than a rigid methodology.
- **Utility in Software Development**:
    - It helps distinguish between different problem types (e.g., well-understood tasks vs. innovative features).
    - Guides the selection of appropriate practices (e.g., when to use detailed upfront analysis versus when to use iterative, feedback-driven approaches like prototyping or spikes).
    - Helps teams understand why requirements might be changing and how to approach uncertainty.
    - Enables a better balance between analysis and feedback in the development process.
## Key Concepts
### Ontology vs. Epistemology
The framework suggests "Ontology should precede Epistemology", meaning understanding the fundamental nature of the situation (ontology) should come before deciding how we know or act (epistemology).
### Causality vs. Correlation
- **Causality**: The direct relationship between cause and effect. In Clear and Complicated domains, cause and effect are perceivable and repeatable. In the Complex domain, cause and effect can only be understood in retrospect. In the Chaotic domain, there is no perceivable relationship between cause and effect.
- **Correlation**: Observing that two things happen together or in a sequence, without necessarily implying a direct causal link.
### Constraint
Constraints are rules or conditions that limit or guide behavior within a domain. Cynefin domains are characterized by different types of constraints:

- Simple: Fixed constraints.
- Complicated: Governing constraints.
- Complex: Enabling constraints.
- Chaotic: No effective constraints.
### Exaptation
"The process by which features acquire functions for which they were not originally adapted or selected". This is particularly relevant in the Complex domain where novel solutions emerge.
## 4 + 1 Domains
### Simple
- **Characteristics**: Stable situations with clear cause-and-effect relationships, evident to anyone. Problems are well-understood.
- **Constraints**: Fixed constraints, tightly constrained, no degrees of freedom.
- **Approach**: **Sense - Categorize - Respond**. Identify the problem type, categorize it based on known solutions, and apply best practices. No deep analysis needed.
- **Software Example**: Programming a turtle to draw a square; very basic, repetitive coding tasks where the solution is known. "If you've done it before, requirements are known".
- **Practices**: Best Practice.
- **Risk**: Complacency (Selbstzufriedenheit) can lead to a "collapse" into Chaos if the situation is misread
### Complicated
- **Characteristics**: Cause-and-effect relationships exist but may not be immediately obvious; they require expertise and analysis to understand. There can be multiple right answers or good practices.
- **Constraints**: Governing constraints, tightly coupled.
- **Approach**: **Sense - Analyze - Respond**. Experts assess the situation, analyze options, and decide on a course of action using good practices.
- **Software Example**: Building a standard CRUD (Create, Read, Update, Delete) form is well-understood by expert teams. "If someone else has done it before, requirements are knowable". Repetitive complicated problems are often automated (e.g., with frameworks like Rails). Automating scenarios with tools like Cucumber can be useful here.
- **Practices**: Good Practice.
### Complex
- **Characteristics**: Cause-and-effect relationships are unpredictable and can only be understood in retrospect. Acting in the space changes the space. This is the realm of high feedback, risk, innovation, and emergent practices. The Agile Manifesto arose from this domain.
- **Constraints**: Enabling constraints, loosely coupled.
- **Approach**: **Probe - Sense - Respond**. Conduct safe-to-fail experiments to understand the environment, sense the patterns that emerge, and then respond by adapting practices.
- **Software Example**: Developing novel web applications with new technologies like Ajax in its early days. "If it's never been done before by anyone, requirements will change". When uncertainty is high, prototyping and spikes are better than trying to eliminate uncertainty with upfront analysis.
- **Practices**: Emergent Practice. This domain is where **exaptation** often occurs.
### Chaotic
- **Characteristics**: No clear cause-and-effect relationships. The situation is highly turbulent and unpredictable. This is a crisis state.
- **Constraints**: No effective constraints, lacking constraint, de-coupled.
- **Approach**: **Act - Sense - Respond**. The immediate priority is to act decisively to stabilize the situation (e.g., get out of the burning house, stem the bleeding). Once stabilized, sense where stability is present and respond to move the situation into another domain (often Complex).
- **Software Example**: A critical production bug brings down a major website on release day, requiring immediate, all-hands-on-deck fixing.
- **Practices**: Novel Practice often emerges from chaos, leading to future safety measures.
### Disorder
- **Characteristics**: This is the space where it's unclear which of the other four domains applies to the situation. People tend to revert to their preferred or most familiar ways of acting, which might not be appropriate.
- **Approach**: The goal is to break the situation down into constituent parts and assign each to one of the other four domains.
# Codefin
Codefin maps software development practices and team dynamics to the Cynefin domains, often using an "East-West Dichotomy" to highlight contrasting approaches suitable for different contexts.

Codefin helps teams and individuals understand **what development practices to apply, when, and why**, depending on the nature of the problem they are trying to solve (as classified by Cynefin).
## Mapping Practices to Domains
By understanding these mappings, teams can consciously choose the most effective tools, techniques, and collaborative models for the specific type of challenge they are addressing:
### Simple
_East/Stable - "Straitjacket architecture", "live in a pattern", "code generator", "test while", "processing jira tickets", "V-model"_

For well-defined, repeatable problems, highly structured or automated approaches can be used. This might involve strict adherence to predefined architectures or patterns, using code generators, or more traditional sequential models for very simple tasks.
### Complicated
_East/Stable - "Evolving architecture", "design with pattern", "static/strong typing", "test first", "pairing", "Scrum"_

When the problem is understood but requires expertise, more structured approaches are useful. This includes evolving an existing architecture, designing with known patterns, using static typing for robustness, Test-First Development (TDD), pair programming for knowledge sharing and quality, and iterative frameworks like Scrum.
### Complex
 _West/Dynamic - "Emerging architecture", "prototype & iterate", "refactor towards pattern", "dynamic/weak typing", "teaming", "Kanban")
 
 For problems where solutions aren't known upfront, practices that support learning and adaptation are key. This includes prototyping, iterating, allowing architecture to emerge, refactoring towards patterns as understanding grows, and using dynamic languages. Team collaboration ("teaming") and flow-based systems like Kanban can be beneficial.
### Chaotic
_West/Dynamic - "Unborn architecture", "ad-hoc mess", "scripting language", "test last", "trial & error", "scouting")_

When facing high uncertainty or a crisis, the approach might be more about rapid exploration, scripting, and getting something working quickly, even if it's messy initially. Practices like "trial & error" and "scouting" (exploration) fit here.
## East-West Dichotomy
This highlights contrasting characteristics and approaches:
### East/Stable
Emphasizes development, delivery, scope-based progress, system thinking, planning, recurrence, reusability, consistency, hard skills, knowledge, rules, intellect, process, features, and tasks. Suited for planners and settlers, applying, and complying.
### West/Dynamic
Emphasizes research, discovery, time-based progress, design thinking, retrospection, emergence, replaceability, diversity, soft skills, mastery, principles, empathy, communication, capability, and objectives. Suited for pioneers and explorers, inventing, and discovering.

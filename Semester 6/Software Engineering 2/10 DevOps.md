# Principles, Practices & Automation
## Evolution of ITs Role
- **1960s/70s (Supporting Role)**: Mainframes made existing processes faster; IT supported the business.
- **1980s (Collaboration)**: PCs led to "Shadow IT" and more direct tech use within business units.
- **1990s/2000s (Technology-Driven Differentiation)**: The Internet enabled IT to provide competitive advantages.
- **Present (Technology is the Business)**: With mobile, AI, and Cloud Computing, technology has become integral to business operations. **Cycle time** (speed of delivery) is key, leading to the rise of DevOps as agile development and operations teams align their priorities.
## Definition of DevOps
- A **holistic business practice** combining people, technologies, cultural practices, and processes to unite previously siloed teams for faster, better software delivery. It's more than just automation.
- A **methodology integrating and automating the work of software development (Dev) and information technology operations (Ops)**. It enables continuous value delivery by bringing people, processes, and products together.
- **From Silos to Shared Workflows**: Before the mid-2000s, Dev, IT Ops, and Security often worked in isolated silos with a linear handoff process (Dev → QA → Ops → Security post-deployment). This was slow and frustrating. DevOps aims to break down these silos.
# Lifecycle
DevOps is often depicted as an infinite loop or a lifecycle. The four main phases are:

1. **Idea (Plan)**: Teams gather requirements and feedback and sketch out necessary resources.
    - _Ideation stack example_: GitHub Issues and Project Boards.
2. **Build (Code, Build, Test)**: Version control and cloud-based development environments facilitate ongoing changes and real-time code review. **Continuous Integration (CI)** uses automated tools to turn code changes into builds, run tests, and prepare code for deployment.
    - _CI stack example_: GitHub Codespaces, GitHub Actions.
3. **Ship (Release, Deploy)**: After initial checks, **Continuous Delivery (CD)** tools automatically push code changes to non-production testing or staging environments. Operations teams can then deploy these changes to production.
    - _CD stack example_: CD pipelines with GitHub Actions, GitHub Packages, Microsoft Azure.
4. **Learn (Operate, Monitor)**: Operations teams monitor releases using tools that measure performance and impact, ensuring stability and uptime. They gather customer feedback and work closely with developers to push fixes and address incidents faster.
    - _Observability stack example_: New Relic, Sentry, Splunk, LGTM
# Agile & DevOps
- DevOps is essentially **Agile applied beyond the software team**, extending its principles to IT Operations.
- Scrum primarily maps to the agile principle "Welcome changing requirements...".
- Continuous delivery primarily maps to "Our highest priority is to satisfy the customer through early and continuous delivery of valuable software”.
- They are complementary ("best friends") and not in tension; thinking Agile means Scrum, and DevOps means Continuous Delivery is an oversimplification
# DORA
**DevOps Research and Assessment (DORA)** provides a standard set of metrics, originating from a team at Google Cloud, to indicate how quickly DevOps can respond to changes, deployment times, iteration frequency, and failure insights.
## Metrics
1. **Deployment Frequency**: Average number of daily finished code deployments to any given environment.
2. **Lead Time for Changes**: Time between acceptance (or code committed) and deployment to production.
3. **Time to Restore Service**: How long it takes to recover from a failure or service incident impacting users.
4. **Change Failure Rate**: Percentage of deployments to production that result in degraded service and require remediation.

**Measuring DORA Metrics**: Can be done through team conversations, the DORA Quick Check, or tools like the `fourkeys` project.
## Report
**DORA Report Highlights (e.g., 2024 data)**:
Elite performers significantly outperform low performers across all metrics. For example, elite performers have lead times of less than one day and deploy on-demand, while low performers take one to six months for lead time and deploy between once per month and once every six months. Elite performers also have much lower change failure rates (e.g., 5% vs. 40%) and faster recovery times (e.g., <1 hour vs. 1 week-1 month).
# Software Automation
**Definition**: The act of scripting or automating a wide variety of daily tasks performed by software developers and operators.

**Why Automate?**: To address issues like inconsistent local builds ("It runs on my computer!"), lack of consistent versioning and unit testing, unknown build states, undefined dependencies, non-transparent and error-prone manual work. Automation also serves as documentation and raises confidence.
## Execution Types
- **On-Demand**: Run by initiating a script or pressing a button.
- **Scheduled**: Run at predetermined times (e.g., nightly builds).
- **Triggered**: Run in response to specific events (e.g., a commit/push to VCS).
## Main Goals of Automation
1. **Improve Product Quality**: Through automated testing, code auditing, and build history.
2. **Faster Time To Market (Cycle Time)**: Accelerate build-to-deployment, enable immediate feedback, shorten innovation cycles.
3. **Minimize Risks**: Prove software builds, find broken builds early, maintain status awareness, eliminate key personnel dependencies (contributes to better Time to Restore Services and Change Failure Rate).
## Types of Automation Tasks
- **Build Automation**: Compiling, packaging, creating documentation/release notes.
- **Test Automation**: Automated Unit, Integration, and Acceptance Tests.
- **Deployment Automation**: Automated deployment to Test or Production.
- **Operation Automation**: Infrastructure provisioning, monitoring, health management, scaling.
# Software Automation Pipeline (CI/CD)
A sequence of automated steps to move software from development to operation, implemented at every stage (Dev, Integration, QA, Operation). Each step typically requires passing tests; otherwise, a feedback loop notifies responsible people, and the process halts until fixed.

**Levels of Automation / Pipeline Stages**:
1. **Build Automation**: Building individual components and running unit tests locally by the developer. Includes dependency resolution, compiling, packaging. _Tools examples: `make`, `npm`, `MSBuild`, `Gradle`/`Maven`        
2. **Continuous Integration (CI)**: Automatically build, test (unit, integration, code audit, security, UI, DB), and integrate components. An important XP Practice, typically run on a CI Server.
3. **Continuous Delivery (CD)**: Extends CI by also creating releases, deploying them to a staging environment, and running automatic acceptance tests (stress, load, compliance). Software is ready for production, but final deployment requires a manual step.
4. **Continuous Deployment (CD)**: Extends Continuous Delivery by automatically deploying to production after successfully passing acceptance tests. Releasing many small updates reduces risk and downtime.
5. **DevOps (Operations Automation)**: Encompasses automating the operation of the production system (configuration management, infrastructure provisioning, backup, monitoring, automatic health management, scaling, etc.).
# Continuous Integration (CI)
Effective CI involves several key practices:

1. **Use a Version Control System (VCS)**: All project assets (code, scripts, configurations) are stored in a version-controlled mainline (e.g., `main` or `trunk`), representing the current deployable state.
2. **Automate the Build**: The entire build process must be automated.
3. **Make the Build Self-Testing**: Automated tests serve as a health check for the codebase; the test suite must be kept updated.
4. **Everyone Pushes Commits to Mainline Every Day**: Frequent integration facilitates communication about changes among developers.
5. **Fix Broken Builds Immediately**: The mainline must always be in a healthy, buildable state.
6. **Keep the Build Fast**: Builds should complete quickly (e.g., < 10 minutes) for rapid feedback.
7. **Team Responsibilities**:
    - Check in frequently.
    - Don't check in broken or untested code.
    - Don't check in when the build is broken.
    - Ensure the system builds successfully after checking in.
8. **Integrate Often, Even Before Features are Fully Formed**: Integrate with healthy builds as soon as there's forward progress. Latent code (part of unfinished features) should still be exercised in tests.
9. **Test in a Clone of the Production Environment**: The test environment should mimic production as closely as possible (OS, DB versions, etc.) to identify issues under controlled conditions and minimize discrepancies. Virtualization, containerization, and IaC make this easier.
## Hide Work-in-Progress
Manage latent code in live releases to avoid exposing half-developed features. Techniques include:

- **Feature Flags (Feature Toggles)**: Allows turning features on/off at runtime without redeploying. Configuration settings control code path execution, enabling decoupled deployment and release.
- **Keystone Interface**: For large-scale changes, define a new stable interface. New components implement this, and the existing system is refactored or adapted to use it, allowing gradual, safe integration.
- **Dark Launching**: Release new features to production invisibly to users to test performance and stability under real load. The new code runs, but results aren't shown, or user behavior isn't altered.
- **Parallel Change (Expand-Contract)**: A pattern for making breaking changes to interfaces or data schemas by first expanding to support both old and new, then migrating clients, then contracting to remove the old.
- **Branch By Abstraction**: Make large-scale changes to a codebase by introducing an abstraction layer over the part being changed. Clients use the abstraction, allowing the underlying implementation to be replaced incrementally.
## Automate Deployment
With CI, deployment can become the bottleneck; automate it. This includes scripting environment creation. This enables Continuous Deployment, with teams potentially deploying multiple times a day. Automated deployment practices:

- **Automated Rollback**: Quickly revert to a last known good state if a deployment fails.
- **Blue/Green Deployment**: Maintain two identical production environments ("Blue" and "Green"). Live traffic goes to one (e.g., Blue). Deploy the new version to the other (Green). After testing Green, switch traffic to it. Blue becomes standby or the next deployment target. Allows for instant rollback by switching traffic back.
- **Canary Releases**: Gradually roll out a new version to a small subset of users/servers. Monitor behavior and performance. If all is well, gradually expand the rollout to the entire user base. Reduces the blast radius of potential issues.
# Concepts for Automation
## Virtualisation
Technology creating virtual versions of physical computing resources using software (hypervisor) to simulate hardware, allowing multiple Virtual Machines (VMs) on one physical machine. Each VM includes apps, dependencies, and a full guest OS.
## Containerisation
Provides an isolated, resource-controlled, portable operating environment where an application and its dependencies run as isolated processes on the host OS, sharing the OS kernel. Containers are lighter than VMs.

_Tools_: Docker for containers, Kubernetes for container orchestration
## Infrastructure as Code (IaC)
Managing and provisioning IT infrastructure (networks, VMs, etc.) using code/scripts stored in a VCS, instead of manual configuration. Key for DevOps, involving developers in configuration and Ops earlier in development.
# Microservice Architecture
**Definition**: An architectural style structuring an application as a collection of loosely coupled, independently deployable services. Each service typically focuses on a specific business capability or domain.

**Communication**: Services communicate via well-defined APIs (e.g., RESTful protocols).

**Deployment**: Often packaged as containers (Docker) and managed by orchestration tools (Kubernetes).

**Fault Tolerance**: Achieved through techniques like circuit breakers, retries, distributed tracing, and monitoring.

**Fit with Agile/DevOps**:
- **Independent Development & Deployment**: Decentralization allows different agile teams to develop, deploy, and scale services independently.
- **Technology Diversity**: Teams can use technologies best suited for their specific service.
- **Faster Release Cycles**: Aligns with DevOps goals, as changes to one microservice don't require redeploying the entire application.
- **Team Autonomy**: Supports smaller, focused teams owning services end-to-end.
- **Scalability & Resilience**: Individual services can be scaled independently.
# GitHub Actions
**Definition**: A CI/CD platform by GitHub to automate build, test, and deployment pipelines within a repository. Workflows are defined in YAML files in `.github/workflows/`.

**Key Components**:
- **Workflows**: Configurable automated processes with one or more jobs, defined by YAML, triggered by events, manually, or on schedule.
- **Events**: Specific repository activities that trigger a workflow (e.g., push, pull request).   
- **Jobs**: Sets of steps in a workflow executing on the same runner; steps run in order, can share data. Dependencies can exist between jobs.
- **Actions**: Reusable custom applications for complex, repeated tasks; can be custom-written or from GitHub Marketplace.
- **Runners**: Servers that run workflows when triggered; each runs one job at a time. GitHub provides Linux, Windows, and macOS runners.
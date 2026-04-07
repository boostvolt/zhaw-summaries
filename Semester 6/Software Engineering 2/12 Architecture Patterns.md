# CQRS (Command Query Responsibility Segregation)
**Definition**: CQRS is an architectural pattern that separates the model for **writing** data (Commands) from the model for **reading** data (Queries). Instead of a single data model for both read and write operations, you have two distinct models optimized for their specific tasks.
## How it works
- **Commands**: Represent an intent to change the state of the system (e.g., `CreateOrderCommand`, `UpdateUserDetailsCommand`). They are processed by a "write model" or "command side" which handles business logic and data persistence. Commands typically do not return data.
- **Queries**: Represent a request for data. They are handled by a "read model" or "query side" which is optimized for querying and often uses denormalized data stores or views tailored for specific read use cases. Queries do not modify state.
## Benefits
- **Scalability**: Read and write workloads can be scaled independently. The read side can be heavily optimized with multiple read replicas, different database technologies, or caching strategies without impacting the write side.
- **Performance**: Read models can be highly optimized for specific query needs, leading to faster reads. The write model can focus on transactional consistency and business rule enforcement.
- **Flexibility**: Different data models and even different database technologies can be used for the read and write sides, choosing the best fit for each purpose.
- **Complexity Management**: By separating concerns, each model can be simpler and more focused.
## Considerations
- Introduces eventual consistency between the write and read models if they are separate data stores, which needs tobe managed.
- Increases system complexity overall due to separate models and data synchronization logic.
- Best suited for complex domains or systems with distinct read/write scaling needs.
# Event Sourcing
**Definition**: Event Sourcing is a pattern where all changes to an application's state are stored as a sequence of immutable "events." Instead of storing the current state of an entity directly, you store the history of events that have affected that entity.
## How it works
- When something significant happens in the application (e.g., `OrderCreated`, `ItemAddedToCart`, `PaymentProcessed`), an event object is created and appended to an event store (an append-only log).
- The current state of an entity is derived by replaying all the events related to that entity in order.
- Aggregates (a DDD concept representing a consistency boundary) process commands and produce events.
## Benefits
- **Audit Trail**: Provides a complete, reliable audit log of all changes made to the system, as every state change is an event.
- **Temporal Queries**: Allows querying the state of an entity at any point in time by replaying events up to that point.
- **Debugging and Root Cause Analysis**: Easier to understand how an entity reached its current state by examining the sequence of events.
- **Flexibility in Projections**: Different read models (projections) can be built from the same event stream to serve various query needs. If a new read model is needed, events can be replayed to build it.
- Often used in conjunction with CQRS, where the event store is the write model and projections are the read models.
## Considerations
- Deriving current state by replaying events can be complex or slow for entities with very long histories (mitigated by snapshots).
- Event schema evolution needs careful management.
- Requires a shift in thinking from state-based persistence to event-based persistence.
# Strangler Pattern
**Definition**: An architectural approach for incrementally replacing or modernizing a legacy system. New functionality is built around the edges of the old system, gradually "strangling" it until the legacy system can be decommissioned.
## How it works
1. Identify a part of the legacy system to be replaced or a new feature to be added.
2. Build this new functionality as a separate service or module using modern technologies and practices.
3. Introduce a routing mechanism (e.g., a facade, proxy, API gateway, or load balancer) that intercepts requests.
4. Initially, the router directs calls to the legacy system. As new services come online, the router progressively directs relevant calls to the new services.
5. Over time, more functionality is moved to the new system, and less traffic goes to the legacy system.
6. Eventually, the legacy system is "strangled" and can be retired.
## Benefits
- **Reduced Risk**: Allows for incremental modernization, reducing the risk associated with a big-bang replacement.
- **Continuous Delivery**: New features and improvements can be delivered continuously in the new system while the old system still operates.
- **Technology Modernization**: Enables adoption of new technologies and architectures gradually.
- **Value Delivery**: Users can start benefiting from new functionality earlier.
## Considerations
- Requires careful planning of the routing mechanism and interfaces between old and new systems.
- Can lead to temporary increases in complexity as two systems are running and integrated.
- Long-lived; the "strangling" process can take considerable time.
# Online-Migration
**Definition**: The process of migrating data or a system from an old version/platform to a new one **while the system remains operational and accessible to users**, minimizing or eliminating downtime.
## How it works
This is a broad category with various techniques. It often involves:

- Running both the old and new systems in parallel for a period.
- Synchronizing data between the old and new systems in real-time or near real-time.
- Gradually shifting traffic or users from the old system to the new system (can be used with Strangler Fig, Blue/Green, or Canary Releases).
- Techniques might include data replication, dual writes, event-driven synchronization, or using a proxy to manage traffic.
## Benefits
- **High Availability**: Minimizes service disruption for users.
- **Reduced Risk**: Allows for testing and validation of the new system with live traffic before fully decommissioning the old one.
- **Rollback Capability**: Often provides easier rollback paths if issues arise with the new system.
## Considerations
- Can be significantly more complex to implement than offline migrations.
- Requires robust data synchronization mechanisms and careful planning of the cutover strategy.
- May require temporary increases in infrastructure resources to run both systems.
# Circuit Breaker
**Definition**: A resilience pattern used to prevent an application from repeatedly trying to execute an operation that is likely to fail, especially when calling remote services.
## How it works
The circuit breaker acts like an electrical circuit breaker. It monitors calls to a protected function or service.

- **Closed State**: Calls pass through. If a configured number of failures occur (e.g., timeouts, exceptions), the breaker "trips" and moves to the Open state.
- **Open State**: Calls are immediately rejected (fail fast) without attempting the operation. A timer is typically started.
- **Half-Open State**: After the timeout expires, the breaker allows a limited number of test calls to pass through. If these succeed, the breaker resets to Closed. If they fail, it returns to Open, and the timeout restarts.
## Benefits
- **Prevents Cascading Failures**: Stops a failing service from overwhelming itself or downstream systems with repeated requests.
- **Fail Fast**: Provides immediate feedback to the caller when a service is known to be unhealthy, rather than waiting for timeouts.
- **Graceful Degradation**: Allows the system to handle failures gracefully, potentially by returning cached data or default responses.
- **Automatic Recovery**: Can automatically detect when the failing service becomes available again.
## Considerations
- Requires careful tuning of failure thresholds, timeouts, and reset conditions.
- Logging and monitoring of circuit breaker states are important.
# Bulkhead (Schottwand)
**Definition**: A resilience pattern that isolates elements of an application into pools so that if one fails, the others will continue to function. It's named after the bulkheads in a ship's hull that prevent a single breach from sinking the entire ship.
## How it works
- Resources (like connection pools, thread pools, or even separate service instances) are partitioned
- If a fault occurs in one partition (e.g., a service instance becomes unresponsive, a thread pool is exhausted), it's contained within that bulkhead and doesn't affect other parts of the application.
## Benefits
- **Fault Isolation**: Prevents failures in one part of the system from cascading and taking down the entire application.
- **Improved Resilience**: Increases the overall fault tolerance of the system.
- **Resource Management**: Helps manage and limit the resources consumed by different parts of the application.
## Considerations
- Can increase complexity in managing the partitioned resources.
- Requires careful identification of appropriate boundaries for isolation.
# Retry
**Definition**: A resilience pattern where an application automatically retries a failed operation one or more times, assuming the failure might be transient (temporary).
## How it works
- When an operation (e.g., a network call to another service) fails due to a potentially transient error (like a temporary network glitch or a service being briefly unavailable), the application waits for a short period and then attempts the operation again.
- Strategies include fixed delays, exponential backoff (increasing the delay between retries), and adding jitter (randomness to delays) to avoid thundering herd problems.
- Usually, a maximum number of retry attempts is configured.
## Benefits
- **Handles Transient Faults**: Can transparently overcome temporary issues without failing the overall operation.
- **Improved Availability**: Makes the system appear more reliable to users by masking short-lived problems.
## Considerations
- **Idempotency**: The operation being retried should ideally be idempotent (i.e., performing it multiple times has the same effect as performing it once) to avoid unintended side effects.
- **Retry Storms**: Too many aggressive retries can overwhelm a struggling service. Exponential backoff and jitter help mitigate this.
- Not suitable for non-transient failures.
- Maximum retry limits are crucial.
# Serverless
**Definition**: A cloud computing execution model where the cloud provider dynamically manages the allocation and provisioning of servers. Developers write and deploy code without managing the underlying infrastructure. Code is typically executed in stateless compute containers that are event-triggered, ephemeral, and fully managed by the cloud provider (e.g., AWS Lambda, Azure Functions, Google Cloud Functions).
## How it works
- Developers write functions (small, single-purpose pieces of code).
- These functions are triggered by events (e.g., an HTTP request, a new file in storage, a message in a queue).
- The cloud provider automatically provisions resources, runs the function, and then scales down (often to zero) when not in use.
- Billing is typically based on the number of executions and the resources consumed during execution (pay-as-you-go).
## Benefits
- **No Server Management**: Developers don't need to provision, patch, or manage servers.
- **Scalability**: Automatic scaling based on demand.
- **Cost Efficiency**: Pay only for what you use; no cost for idle time (in many FaaS models).
- **Faster Development Cycles**: Focus on code rather than infrastructure.
## Considerations
- **Vendor Lock-in**: Code might be tied to a specific cloud provider's FaaS platform.
- **Cold Starts**: There can be latency the first time a function is invoked after a period of inactivity.
- **Limitations**: Execution time limits, memory limits, and statelessness can be constraints.
- **Debugging & Monitoring**: Can be more complex in distributed serverless architectures.
- Not suitable for all workloads (e.g., long-running, stateful computations might be better on other models).
# Microservices
**Definition**: An architectural style that structures an application as a collection of small, autonomous, and independently deployable services. Each service is built around a specific business capability and communicates with other services typically over a network using lightweight protocols (e.g., HTTP/REST, gRPC, message queues).
## How it works
- The application is decomposed into fine-grained services.
- Each service has its own codebase, data store (often), and can be developed, tested, deployed, and scaled independently.
- Teams are often organized around services, promoting ownership.
## Benefits
- **Technology Diversity**: Different services can be written in different languages/technologies.
- **Independent Scalability**: Scale individual services based on their specific needs.
- **Improved Fault Isolation**: Failure of one service (if designed well) might not bring down the entire application.
- **Faster Release Cycles**: Services can be updated and deployed independently, enabling more frequent releases.
- **Team Autonomy & Specialization**: Smaller, focused teams can own and develop services.
- **Better alignment with Agile/DevOps practices**.
## Considerations
- **Increased Operational Complexity**: Managing many distributed services, their deployment, monitoring, and inter-service communication.
- **Distributed System Challenges**: Dealing with network latency, eventual consistency, distributed transactions.
- **Testing Complexity**: End-to-end testing can be more complex.
- **Requires mature DevOps practices** for effective management.
- Service discovery, load balancing, and resilience patterns (like Circuit Breaker, Retry) become crucial.
# Self-contained Systems
**Definition**: An architectural approach where a web application is decomposed into several functionally distinct, independently deployable units called Self-Contained Systems. Each SCS focuses on a specific domain or feature set and includes its own web UI, business logic, and (optionally) its own dedicated database.
## How it works
- Each SCS is a fully functional mini-application.
- Integration between SCSs happens primarily at the UI level (e.g., via hyperlinks) or through asynchronous mechanisms (e.g., events, shared read-only data sources). Synchronous backend-to-backend calls are typically avoided or minimized.
- An SCS should be runnable and deployable on its own.
## Benefits
- **Team Autonomy**: Different teams can develop, deploy, and scale their SCSs independently.
- **Technology Diversity**: Teams can choose appropriate technologies for their SCS.
- **Improved Resilience**: Failure in one SCS is less likely to affect others.
- **Scalability**: Individual SCSs can be scaled independently.
- Clearer boundaries and ownership.
## Considerations
- Potential for data duplication or consistency challenges if each SCS has its own database.
- Requires careful thought about UI integration and overall user experience.
- Managing shared assets (like CSS, common UI components) across SCSs needs a strategy.
- Can be seen as a coarser-grained alternative to microservices, often with a stronger emphasis on UI integration.
# Monolith (Modulith)
## Definition
- **Monolith**: A traditional architectural style where an entire application is built and deployed as a single, unified unit. All components (UI, business logic, data access) are tightly coupled and run in the same process.
- **Modulith (Modular Monolith)**: A variation of the monolith where the application, while still deployed as a single unit, is internally structured into well-defined, loosely coupled modules with clear interfaces. This aims to bring some of the benefits of modularity (like better organization and testability) to a monolithic deployment.
## How it works
- **Monolith**: All code is in a single codebase, built into a single executable or deployable artifact.
- **Modulith**: Code is organized into internal modules. Communication between modules within the monolith typically happens via direct method calls or well-defined internal APIs, avoiding tight coupling where possible.
## Benefits
- **Simplicity (initially)**: Easier to develop, test, and deploy in the early stages, especially for smaller applications or teams.
- **Performance**: In-process communication between components is very fast.
- **Easier Debugging/Tracing**: Tracing operations within a single process can be simpler.
- **Modulith specific**: Better internal organization, maintainability, and testability compared to a "big ball of mud" monolith, while retaining deployment simplicity.
## Considerations
- **Scalability Challenges**: Scaling usually means scaling the entire application, even if only a small part is a bottleneck.
- **Technology Stack Rigidity**: Difficult to adopt new technologies for parts of the application without impacting the whole.
- **Deployment Risks**: A change in any part requires redeploying the entire application, potentially leading to longer deployment times and higher risk.
- **Maintainability Issues (for large monoliths)**: Can become complex and hard to understand and change over time, especially if modularity is not enforced (leading to the "big ball of mud").
- **Longer Build Times** as the codebase grows.
- Difficult for large, distributed teams to work on concurrently without conflicts.
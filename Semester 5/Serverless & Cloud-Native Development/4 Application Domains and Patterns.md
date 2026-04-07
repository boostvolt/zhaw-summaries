# Software Design Patterns
## Observer (behavioural)
The **Observer** pattern is used to create a subscription mechanism where one object (the _subject_) notifies multiple dependent objects (the _observers_) of any changes in its state. This pattern is useful when a change in one object requires updating others, without tightly coupling them.

**Components**
- **Subject**: The object being observed.
- **Observer**: The objects that react to changes in the subject.
- **ConcreteSubject**: The actual implementation of the subject.
- **ConcreteObserver**: The actual implementation of the observer.

**Use Case**: UI components updating automatically when data changes, event-driven systems.
## Decorator (structural)
The **Decorator** pattern allows for dynamically adding new functionality to an object without modifying its structure. This pattern involves wrapping an object with another to extend its behavior.

**Components**
- **Component**: The base interface or class.
- **ConcreteComponent**: The class implementing the core functionality.
- **Decorator**: The base class for all decorators.
- **ConcreteDecorator**: The class that adds additional behavior to the component.

**Use Case**: Enhancing or modifying object behavior in systems where flexibility is required, such as adding features to UI elements or adding responsibilities to objects in a flexible way.
# Industrial Patterns
## Monolith
A **Monolith** is a traditional software architecture where all components of the application are tightly integrated and run as a single, unified unit. In this model, the frontend, backend, and all internal components (e.g., database, business logic) are packaged together, making it simpler to develop initially but harder to scale and maintain as the application grows.

**Pros**
- Simplicity in deployment and testing.
- Easier to manage in small to medium-sized projects.

**Cons**
- Difficult to scale horizontally.
- Harder to maintain as the codebase grows.
- Changes in one part of the system can affect the entire application.
## N-Layers
The **N-Layers** architecture organizes the application into distinct layers, each responsible for a specific set of tasks. Common layers include:
- **Presentation Layer**: Handles user interaction (UI).
- **Business Logic Layer**: Contains the core functionality of the application.
- **Data Access Layer**: Manages interactions with the database or external data sources.
- **Others**: Layers like Service, Application, or Security might be added.

**Pros**
- Separation of concerns.
- Easier to maintain and extend.
- Better testability and flexibility.

**Cons**
- Can introduce complexity.
- Slower performance due to multiple layers of abstraction.
## Microservices
**Microservices** is an architectural style where the application is built as a collection of small, independent services that communicate over a network (usually HTTP/REST or messaging protocols). Each microservice focuses on a specific business functionality and can be developed, deployed, and scaled independently.

**Pros**
- Highly scalable and flexible.
- Independent deployment and testing.
- Better fault isolation.

**Cons**
- Increased complexity in communication and coordination.
- Potential overhead in managing multiple services (e.g., service discovery, inter-service communication).
- Requires more infrastructure (e.g., container orchestration, monitoring).

**Use Case**: Large-scale, complex applications that require high scalability, flexibility, and independent service management (e.g., e-commerce platforms, streaming services).
# Composition Patterns
## Routing Function
The **Routing Function** pattern is used to route requests or tasks to different services, functions, or handlers based on certain conditions or criteria. The function determines where to send the request or task, enabling flexible and dynamic control flow in distributed systems.

**Use Case**
- In microservices, routing functions can decide which service handles a particular request based on factors like request type, user preferences, or load balancing.
- In serverless architectures, a routing function might decide which function to invoke based on input data.

**Benefits**
- Allows flexible control over which service or function is invoked.
- Enables dynamic routing based on conditions (e.g., URL, headers, or request content).
## Fan-in / Fan-out
The **Fan-in** and **Fan-out** patterns deal with the flow of data between services or functions, especially in systems with multiple sources or destinations.

**Fan-out**: This pattern involves sending a single request or event to multiple receivers or services in parallel. It is used to distribute tasks or data to multiple services to handle different parts of the process concurrently.
**Use Case**: Event-driven systems where one event triggers multiple downstream processes or services.

**Fan-in**: This pattern involves collecting multiple responses or data streams into a single stream or service for further processing. It is used to aggregate results from multiple sources into one.
**Use Case**: After multiple services have processed parallel tasks, their results are merged into one service for final aggregation or decision-making.

**Benefits**
- **Fan-out** increases throughput by parallelizing work.
- **Fan-in** consolidates data from multiple sources for processing.
- Both patterns enhance scalability, fault tolerance, and reduce bottlenecks by distributing tasks effectively.
# Function Patterns
## Periodic invocation
The **Periodic Invocation** pattern triggers a function at regular intervals, regardless of events or user actions. It is often used for tasks that need to run on a schedule, such as cleanup processes, data synchronization, or reporting.

**Use Case**
- Scheduling tasks like backups, health checks, or routine system maintenance.
- Running periodic data aggregation or analytics.

**Benefits**
- Automates repetitive tasks.
- Ensures timely execution of tasks without manual intervention.
## Event-driven
The **Event-driven** pattern is based on triggering functions in response to events or changes in system state. This pattern is common in serverless architectures where functions are activated by events like HTTP requests, database changes, or external notifications.

**Use Case**
- Responding to user actions like form submissions, file uploads, or clicks.
- Reacting to changes in data or external events (e.g., a new message in a queue, IoT device state change).

**Benefits**
- Decouples components for flexibility.
- Promotes scalability, as functions can be triggered only when necessary.
## Data transformation
The **Data Transformation** pattern involves processing and converting data from one format or structure to another. This can include operations such as data enrichment, filtering, aggregation, or format conversion.

**Use Case**
- Converting data between different APIs or systems.
- Aggregating raw data into a more usable format (e.g., transforming logs into structured analytics data).

**Benefits**
- Centralizes and standardizes data manipulation.
- Simplifies integration with external systems by providing consistent data formats.
## Data streaming
The **Data Streaming** pattern enables the continuous flow of data, processed in real-time or in small chunks. This is often used for scenarios that require processing large volumes of data with low latency, such as real-time analytics or monitoring systems.

**Use Case**
- Analyzing logs, sensor data, or live user activity in real time.
- Streaming media, such as video or audio, with continuous processing.

**Benefits**
- Provides real-time insights and immediate reactions to incoming data.
- Efficiently handles large-scale data with minimal delay.
## State machine
The **State Machine** pattern represents a process with distinct states and transitions between those states. Functions are triggered based on state changes, and each state can have its own set of behaviors. This pattern is useful in systems with defined workflows or process control.

**Use Case**
- Implementing workflows, such as order processing, approval workflows, or payment systems.
- Modeling lifecycle states of entities (e.g., user account states or device status).

**Benefits**
- Provides clear structure to complex workflows.
- Helps maintain predictable system behavior by clearly defining state transitions.
# 1-Node, 1-Container Patterns
## Upward interface container
An **Upward Interface Container** refers to a software or system architecture pattern where an interface (usually an abstraction layer or container) provides upward communication from lower levels of the system to higher levels. It acts as a middleware or intermediary between components, enabling communication and data flow in an upward direction within the application stack or system.

**Use Case**
- In multi-layered applications, an upward interface container might allow lower-level services or data layers to interact with higher-level user-facing components or interfaces.
- Used in systems where abstraction is needed to simplify or modularize complex interactions.

**Benefits**
- Improves system modularity and separation of concerns.
- Centralizes communication handling between various components.
## Downward interface platform
A **Downward Interface Platform** typically refers to a system or platform where higher-level components or abstractions interface with lower-level system services, hardware, or infrastructure. The flow of control or communication moves from top to bottom, where the platform provides an abstraction for underlying components.

**Use Case**
- In containerized environments, the downward interface allows higher-level applications to communicate with lower-level infrastructure or hardware.
- Used in cloud-native or platform-as-a-service (PaaS) environments to connect software components to hardware or cloud services.

**Benefits**
- Enables interaction between software applications and lower-level system components or services.
- Centralizes complex infrastructure or system-level communication, making it easier to manage and scale.
## Containers
**Containers** are a lightweight form of virtualization that allows software applications to run consistently across different computing environments. They encapsulate an application and its dependencies (e.g., libraries, configurations) into a single unit that can be deployed and executed on any system supporting containerization.

**Use Case**
- Microservices architectures, where each service is packaged in its own container for isolation and independent scaling.
- Deploying applications in a consistent environment across development, staging, and production.

**Benefits**
- Portability: Containers can run on any platform that supports containerization (e.g., Docker, Kubernetes).
- Scalability: Containers can be quickly deployed, scaled, and managed across large clusters.
- Efficiency: Lightweight and resource-efficient compared to traditional virtual machines.
# 1-Node, n-Container Patterns
## Sidecar / Sidekick
The **Sidecar** pattern involves running a secondary container alongside a primary application container within the same pod or node. The sidecar complements the primary container by handling auxiliary tasks such as logging, monitoring, or proxying.

**Use Case**
- Logging and metrics collection (e.g., forwarding logs to a centralized system).
- Service mesh proxies (e.g., Envoy in Istio).

**Benefits**
- Modularizes functionality without altering the primary application.
- Reusable across multiple services.
## Ambassador
The **Ambassador** pattern places a container as an intermediary between the primary container and external services. It acts as a proxy that handles communication, such as managing API requests, retries, or service discovery.

**Use Case**
- Managing outbound connections in microservices (e.g., API gateways or load balancers).
- Implementing advanced networking logic, such as retries or caching.

**Benefits**
- Decouples external communication logic from the primary container.
- Simplifies the integration of external services.
## Adapter
The **Adapter** pattern, in the context of containers, involves an additional container that translates data or requests between the primary container and external systems. It adapts mismatched interfaces or protocols to enable seamless communication.

**Use Case**
- Converting data formats for legacy systems.
- Bridging communication between incompatible protocols.

**Benefits**
- Enables integration with legacy systems or incompatible services.
- Reduces complexity by isolating the adaptation logic.
# m-Nodes, n-Containers Patterns
## Leader election
The **Leader Election** pattern is used to ensure that one node or container in a distributed system acts as a coordinator, leader, or decision-maker at any given time. This is crucial for avoiding conflicts and ensuring consistency.

**Use Case**
- Coordinating tasks in a distributed system, like assigning work or maintaining state.
- Implementing consensus algorithms (e.g., Raft, Paxos).

**Benefits**
- Ensures only one node acts as the leader, preventing race conditions.
- Improves reliability by enabling leader failover.
## Work queue
The **Work Queue** pattern distributes tasks or jobs to multiple nodes or containers for parallel processing. A central queue holds the tasks, and workers consume tasks as they become available.

**Use Case**
- Batch processing, such as image rendering or data processing.
- Asynchronous task handling in distributed systems.

**Benefits**
- Scales workload across multiple workers.
- Improves fault tolerance by allowing tasks to be re-queued if a worker fails.
## Scatter / Gather
The **Scatter/Gather** pattern involves splitting a task into smaller subtasks (scatter) that are processed across multiple nodes or containers. The results of these subtasks are then aggregated (gather) to produce a final result.

 **Use Case**
- Distributed search engines (e.g., querying across shards).
- Parallel processing systems like MapReduce.

**Benefits**
- Speeds up processing by distributing workloads.
- Aggregates results efficiently for large-scale computations.
## Operator
The **Operator** pattern automates the deployment, scaling, and management of applications or workloads in distributed systems. Operators are implemented as containers that encode domain-specific knowledge to manage the lifecycle of complex applications.

**Use Case**
- Kubernetes custom resource management.
- Automating tasks like backups, updates, or scaling in stateful applications (e.g., databases).

**Benefits**
- Simplifies management of complex, stateful applications.
- Reduces manual intervention by automating operational tasks.
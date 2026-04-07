# Fog vs. Edge Computing
**Fog Computing** extends cloud capabilities closer to the edge of the network, processing data in a distributed manner across local nodes. It acts as an intermediary layer between edge devices and the cloud, reducing latency and bandwidth usage.

**Edge Computing** processes data directly on devices or local nodes at the data source (e.g., sensors, IoT devices), enabling real-time decision-making with minimal delay.

**Key Differences**
- **Fog Computing**: Decentralized, distributed processing across multiple nodes between devices and cloud.
- **Edge Computing**: Localized processing on or near the device, reducing reliance on external infrastructure.

**Use Cases**
- **Fog**: Large-scale IoT systems, where data needs to be aggregated and analyzed before sending to the cloud.
- **Edge**: Time-sensitive applications like autonomous vehicles or smart sensors.
# Traditional vs. IaaS, PaaS, SaaS
![[IMG_CF21B7E107B2-1.jpeg]]
# FaaSification
**FaaSification** is the process of adapting traditional codebases to Function-as-a-Service (FaaS) paradigms. It involves four key steps:

1. **Code Analysis**: Identifying modular and independent parts of the application that can be converted into serverless functions.
2. **Code Transformation**: Refactoring or rewriting code to meet FaaS constraints, such as statelessness and limited execution time.
3. **Deployment**: Packaging and deploying functions to a FaaS platform (e.g., AWS Lambda, Azure Functions).
4. **On-Demand Activation**: Configuring functions to be triggered by specific events (HTTP requests, database changes, etc.) for cost-effective, scalable execution.

**Goal**: Optimize applications for scalability, cost-efficiency, and cloud-native operation.

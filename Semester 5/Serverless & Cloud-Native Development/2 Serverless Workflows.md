# Function Prewarming
**Function Prewarming** ensures that serverless functions (e.g., AWS Lambda) are ready to execute requests without the latency caused by a cold start. A **cold start** occurs when a serverless platform initializes a new execution environment due to inactivity or scaling events, which can delay response times.

1. **Periodic Invocations**: Triggering the function at intervals to keep it “warm.”
2. **Provisioned Concurrency**: Allocating resources in advance to maintain a pre-initialized state.

Benefits
- Reduces latency for critical applications.
- Improves user experience in performance-sensitive scenarios.

Drawback
- Increased costs due to sustained resource usage.

![[IMG_28840CC2ECE8-1.jpeg]]
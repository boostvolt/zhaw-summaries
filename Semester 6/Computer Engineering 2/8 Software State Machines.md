# Motivation
Embedded systems are often **reactive systems** that must respond to external events from sensors or users. An FSM is an excellent model for describing this event-driven behavior.

While FSMs are used in hardware, the approach in software is fundamentally different:
* **Hardware FSMs** are intrinsically parallel, clock-driven, and evaluate all inputs on every clock edge. Applying this synchronous model to software would be inefficient, creating a large processing load by requiring the CPU to evaluate all inputs even when they haven't changed.
* **Software FSMs** are intrinsically sequential and **event-driven**. The FSM is only evaluated when an input event actually occurs, which is far more efficient for a CPU.
# Core Concepts & Modeling with UML
Software FSMs are modeled using state diagrams, often following the notation of the Unified Modeling Language (UML). The behavior is described by a few core components, similar to a Mealy machine.
## Key Components
* **State**: An internal condition in which the system waits for an event. *e.g., `wash`, `rinse`, `dry` in a car wash*.
* **Initial State**: The state the machine starts in, indicated by a transition from a solid circle. A state diagram must always have one.
* **Event (Input)**: An asynchronous input that can trigger a transition. *e.g., `start`, `stop`, `time_out`*.
* **Action (Output)**: An operation performed when a transition occurs. *e.g., `water_on`, `shampoo_on`*.
* **Transition**: The reaction to an event, which may cause a state change and/or trigger actions. This is labeled on the diagram with the format `Event / Action`.

![[Pasted image 20250606134523.png|800]]
## Semantics and Rules
* **Run-to-Completion**: Once a transition is triggered, it runs to completion and cannot be interrupted by another event.
* **Passive Model**: The FSM only reacts to external events; it does not generate actions on its own.
* **Deterministic**: For any given state and event, there must be only one possible transition defined.
* **Clarity**: To make diagrams easier to read, events that cause no transition or action in a given state are usually omitted from the drawing.

![[Pasted image 20250606134901.png|800]]
# Interaction Between Multiple FSMs
Complex systems can be broken down into multiple, simpler FSMs that interact with each other.
## Ports and Links
FSMs communicate via messages. An action of one FSM can be an output message sent through a **port** over a **link** to another FSM, where it is received as an input event.

![[Pasted image 20250606135808.png|600]]

![[Pasted image 20250606135918.png|800]]
## Event Queue
To manage events from multiple sources without losing any, an **event queue** (typically a FIFO buffer) is used. Events from all sources are added to the queue. The main loop then processes one event at a time from the queue, dispatching it to the appropriate FSM handler.

![[Pasted image 20250606140015.png|800]]
# Implementation in C
## Main Program
The main program initializes the system and periodically checks in a loop if an event has occurred on the slide switches. If an event is detected, it is passed to the state machine for processing.

```c
/*
 * Main program
 *
 * Endless loop to detect and process events
 */
int main(void)
{
    event_t event;

    fsm_init();
    timer_init();
    while (1) {
        event = get_event();
        if (event != NO_SWITCH) {
            fsm_handle_event(event);
        }
    }
}
```
## Enumeration Type Definitions
Enumeration types are defined for states, events, and LEDs.

```c
/* type definitions for states, events and leds */
typedef enum {
    WAIT,
    ALL_ON
} fsm_state_t;

typedef enum {
    NO_SWITCH = 0x00,
    S0 = 0x01, // bit position of switch S0
    S1 = 0x02  // bit position of switch S1
} event_t;

typedef enum {
    NO_LED = 0x00,
    LED0 = 0x01, // bit position of LED0
    LED1 = 0x02, // bit position of LED1
    LED0_LED1 = 0x03 // bit positions LEDO & LED1
} led_t;
```
## Module-Local State Variable
A static variable is used to store the current state internally within the module.

```c
/* use static state variable for module internal usage */
static fsm_state_t state = WAIT;
```
## Reading an Event
This function reads the dip switches and detects a change from 0 to 1 (a rising edge) compared to the last reading. It prioritizes events if multiple occur simultaneously. The `last_switch_value` is `static` to retain its value between calls. It returns a single event.

```c
static event_t get_event(void)
{
    static uint8_t last_switch_value = 0x3; // avoids event @first call
    event_t retval = NO_SWITCH;
    uint8_t all_events;
    uint8_t current_switch_value;

    current_switch_value = DIPSW_07_00;

    // rising edge detection
    all_events = ~last_switch_value & current_switch_value;
    last_switch_value = current_switch_value;

    // handle only one event in case of simultaneous events
    if (all_events & (uint8_t)S0) {
        retval = S0;
    } else if (all_events & (uint8_t)S1) {
        retval = S1;
    }
    timer_wait_for_tick(); // delay for debouncing
    return retval;
}
```
## Outputting Actions
```c
/*
 * Turns LEDs off according to parameters
 * param[in]: leds bitmask indicating LEDS to be turned off
 */
static void led_turn_off(led_t leds)
{
    LED_07_00 &= ~leds;
}

/*
 * Turns LEDs on according to parameters
 * param[in]: leds bitmask indicating LEDS to be turned on
 */
static void led_turn_on(led_t leds)
{
    LED_07_00 |= leds;
}
```
## FSM Initialization
This function initializes the FSM by setting its initial state and performing initial actions.

```c
/* * Initializes the FSM and sets the initial state and actions */ 
static void fsm_init(void) { 
	LED_07_00 = 0x0; // action 
	state = WAIT; // initial state 
}
```
## Processing Events with the FSM
This function implements the FSM logic. It processes a given event based on the current state, sets the new state, and triggers the required actions.

![[Pasted image 20250606141512.png|600]]

```c
/*
 * Finite State Machine implementation
 * The function processes the given event based on the current state.
 * It sets the new state and triggers the required actions
 * param[in]: event the event to be processed
 */
static void fsm_handle_event(event_t event)
{
    /* Implementation FSM */
    switch (state) {
        case WAIT:
            switch (event) { // an if statement could be used alternatively
                case S0:
                    led_turn_on(LED0_LED1); // action
                    state = ALL_ON; // state
                    break;
                default:
                    // S1 is ignored
                    state = WAIT;
            }
            break;
        case ALL_ON:
            switch (event) {
                case S0:
                    led_turn_off(LED0);
                    state = WAIT;
                    break;
                case S1:
                    led_turn_off(LED1);
                    state = WAIT;
                    break;
                default:
                    state = ALL_ON;
            }
            break;
        default:
            state = WAIT;
    }
}
```
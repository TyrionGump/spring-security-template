# SecurityContext & SecurityContextHolder

Spring Security needs a way to associate an authenticated user with each thread handling a request.
It does this by storing a `SecurityContext`—which wraps a single `Authentication` object—in a
thread-local holder (`SecurityContextHolder`). This lets any code on that thread call
`SecurityContextHolder.getContext().getAuthentication()` to find out “who” is running. At the end of
the request, Spring clears the context to prevent data leaking into other requests.
---

## Core Concept

### 1. SecurityContext

- Holds security data for one “execution context” (typically a single HTTP request thread).
- Contains exactly one Authentication (principal, credentials, authorities).

### 2. SecurityContextHolder

- Static façade whose methods delegate to a `SecurityContextHolderStrategy`.
- By default, Spring uses a `ThreadLocalSecurityContextHolderStrategy`, so each thread has its own
  SecurityContext.
- Static methods (`getContext()`, `setContext(...)`, `clearContext()`) actually read/write that
  thread’s
  ThreadLocal storage.

---

## How does it Work in a Web Request?

### Default (ThreadLocal) Behaviour

#### 1. Start of HTTP Request (`SecurityContextPersistenceFilter`)

- Looks in the `HttpSession` for an existing `SecurityContext`.
- If found, loads it into the thread’s `ThreadLocal`; otherwise, creates a fresh
  empty `SecurityContext`.

#### 2. Authentication Phase

When a request reaches Spring Security’s authentication filter (e.g.,
`UsernamePasswordAuthenticationFilter`), the filter extracts credentials (username/password, token,
etc.) and passes them to an `AuthenticationManager`. If authentication succeeds, an Authentication
object (containing principal, authorities, etc.) is returned.

Spring then calls `SecurityContextHolder.getContext().setAuthentication(authResult);` so that
downstream code (controllers, services) can retrieve the authenticated user
via `SecurityContextHolder.getContext().getAuthentication();`. Or, have your components accept
an `Authentication` argument directly—Spring will populate it
automatically.

#### 3. End of HTTP Request (`SecurityContextPersistenceFilter`)

- Save as (possibly updated) `SecurityContext` back into the `HttpSession` (if session-based).
- Calls `SecurityContextHolder.clearContext()` to remove it from the thread's `ThreadLocal`,
  preventing leaks.

```mermaid
---

title: SecurityContextHolder (ThreadLocalSecurityContextHolderStrategy)
---
%%{init: {"themeVariables': { 'fontSize': '12px'}}}%%
graph LR
    subgraph Request_Thread_1[Thread 1]
        direction TB
        SecurityContextHolder1[ThreadLocal SecurityContext 1]
        SecurityContextHolder1 --> Authentication1[Authentication 1]
        Authentication1 --> Principal1(Principal 1)
        Authentication1 --> Credentials1(Credentials 1)
        Authentication1 --> Authorities1(Authorities 1)
    end

    subgraph Request_Thread_2[Thread 2]
        direction TB
        SecurityContextHolder2[ThreadLocal SecurityContext 2]
        SecurityContextHolder2 --> Authentication2[Authentication 2]
        Authentication2 --> Principal2(Principal 2)
        Authentication2 --> Credentials2(Credentials 2)
        Authentication2 --> Authorities2(Authorities 2)
    end

    request_1[Request 1] --> Request_Thread_1 --> response_1[Response 1]
    request_2[Request 2] --> Request_Thread_2 --> response_2[Response 2]
```

### Derived Behaviour

There are several options. Here we briefly introduce `InheritableThreadLocal` mode.

- If you need child threads (e,g, an async task) to inherit the parent's context, you can
  set `SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL)`
- New threads will start with a snapshot of the parent's `SecurityContext`. Changes made later in
  the parent do not flow automatically to the child.
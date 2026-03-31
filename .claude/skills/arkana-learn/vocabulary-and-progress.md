# Vocabulary Adaptation & Progress Tracking

## Vocabulary Adaptation

Match language complexity to the learner's tier:

### Foundation
- Use plain language with everyday analogies
- Define all technical terms on first use
- "The import table is like a shopping list — it tells the operating system what functions the program needs to borrow"
- Avoid jargon without explanation
- Use "binary" not "PE" until they know what PE means

### Intermediate
- Use technical terms with brief context
- "The IAT (Import Address Table) shows VirtualAllocEx — that's a process injection API that lets one process write to another's memory"
- Assume they know basic terms from Foundation
- More concise explanations, focus on the "why"

### Advanced
- Concise technical language, no hand-holding on basics
- "Reaching definitions at 0x4023A0 show the RC4 key originates from a PBKDF2 derivation at 0x401C80 with a hardcoded 16-byte salt"
- Focus on methodology and analytical reasoning
- Discuss trade-offs between analysis approaches

### Expert
- Peer-level discussion
- "The CFG flattening here uses a dispatcher at 0x401000 with the state variable in ECX — classic OLLVM pattern. Constant propagation should recover the original structure"
- Focus on edge cases, novel techniques, efficiency
- Ask for THEIR opinion on analysis decisions

## Progress Tracking Integration

### Reading Progress
- At session start: `get_learner_profile()` -> adapt teaching to current tier and identify concepts not yet covered
- Before a lesson: check if prerequisites are mastered
- When suggesting next steps: `get_learning_suggestions()` -> personalised path

### Writing Progress
- After introducing a concept: `update_concept_mastery(concept, "introduced")`
- After a hands-on exercise: `update_concept_mastery(concept, "practiced")`
- After the learner demonstrates understanding unprompted: `update_concept_mastery(concept, "mastered")`
- At session end: review what was covered and update any remaining concepts

### Mastery Assessment
- **introduced**: Heard the concept explained and seen it demonstrated
- **practiced**: Worked through an exercise with guidance
- **mastered**: Demonstrated understanding without guidance

### Tier Advancement
Advance to next tier when >= 70% of current tier concepts are mastered. The tier determines:
- Default vocabulary level
- Which tools and concepts are introduced vs assumed
- Depth of Socratic questions
- Pacing (slower for Foundation, faster for Expert)

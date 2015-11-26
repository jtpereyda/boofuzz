Sulley Primitives
=================
This document describes the standing design of the Sulley Primitives system.

A Sulley Primitive has an interface partially defined by class BasePrimitive.
The interface consists importantly of:

 * Mutation method.
 * Rendering method.
 * Num-mutations method to get total mutation count.
 * Reset method to reset the primitive to non-mutated state.
 * A name property.
 * Support for reading length.

Most of these interface elements are shared by Blocks and Requests.

Room For Improvement
--------------------
 * Elimination of public variables.
 * Explicit and cohesive interface.
 
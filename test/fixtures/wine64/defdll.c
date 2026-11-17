/* A DLL whose .def (defdll.def) names an export twice, exports its data
 * without DATA, and has an export named `name` (an export, not the keyword) */
int defdll_val = 42;
int defdll_val2 = 7;
int defdll_get(void) { return defdll_val; }

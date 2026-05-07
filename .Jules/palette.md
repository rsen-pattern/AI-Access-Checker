## 2025-05-14 - [Accessibility & Feedback Polishing]
**Learning:** Consistency in form labeling and providing feedback for heavy operations (like PDF generation) significantly reduces user anxiety. Mandatory field indicators are a baseline accessibility requirement that was missing.
**Action:** Always ensure mandatory fields are visually identified with standard conventions (like red asterisks) and use `st.spinner` for operations that trigger a page rerun or take more than a second.

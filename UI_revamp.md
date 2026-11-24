# TASK: COMPLETE UI/UX REDESIGN OF URLSHIELD AI – PROFESSIONAL CYBERSECURITY DASHBOARD

Act as a Senior UI/UX Designer, Frontend Engineer and Streamlit Specialist.

I have an existing, fully developed project named **URLSHIELD AI – AI-Powered Malicious URL Detection System**.

The backend, machine learning models, dataset processing, URL feature extraction, predictions and evaluation functionality have already been implemented.

However, the current Streamlit application's UI is poorly designed. Sections are misaligned, typography is inconsistent, spacing is improper, colors have poor contrast, and the overall application looks unprofessional.

I want you to completely redesign the frontend and transform it into a polished, modern, premium-quality cybersecurity SaaS dashboard.

**IMPORTANT: This is a UI/UX improvement task, NOT a backend redevelopment task.**

Do not remove, break, replace or simplify any existing functionality.

Your primary responsibility is to make the application visually impressive, consistent, intuitive and properly aligned.

## 1. DESIGN DIRECTION

Take inspiration from premium cybersecurity SaaS platforms, modern threat intelligence dashboards and professional analytics applications.

The application should look like a professionally developed commercial cybersecurity product rather than a basic college Streamlit project.

Application identity:

Name: URLSHIELD AI

Tagline: Intelligent URL Threat Detection & Security Analytics

Design style:
- Modern cybersecurity SaaS dashboard.
- Premium dark interface.
- Minimalistic but visually impressive.
- Clean typography.
- Consistent spacing and alignment.
- High readability.
- Professional data visualization.
- Subtle borders and shadows.
- Well-designed interactive elements.

Avoid excessive neon effects, unnecessary gradients, random colors, oversized headings and decorative elements that reduce usability.

## 2. COLOR SYSTEM

Establish a consistent color palette throughout the application.

Use the following colors:

| Element | Color |
|---|---|
| Main background | #0B1120 |
| Sidebar background | #101827 |
| Card background | #151F32 |
| Secondary surface | #1B2940 |
| Primary accent | #22D3EE |
| Secondary accent | #3B82F6 |
| Primary text | #F1F5F9 |
| Secondary text | #A8B5C7 |
| Muted text | #8492A6 |
| Borders | #29384D |
| Success | #22C55E |
| Warning | #F59E0B |
| Danger | #EF4444 |

IMPORTANT:
- Maintain excellent text-to-background contrast.
- Never use dark text on dark backgrounds.
- Never use white text on light input fields.
- All dropdowns, sliders, buttons, tooltips and navigation elements must remain readable.
- Do not mix unrelated colors across different pages.
- Use accent colors selectively.

## 3. TYPOGRAPHY

Fix the typography throughout the application.

Use a modern font such as Inter.

Establish a consistent hierarchy:

- Main page title: 30–34px, semibold or bold.
- Section heading: 21–24px, semibold.
- Card title: 14–16px, medium.
- Main metric: 28–34px, bold.
- Body text: 14–16px.
- Supporting text: 12–13px.
- Sidebar navigation: 14–15px.

Do not make every heading oversized.

Ensure:
- Consistent font family.
- Consistent font weights.
- Proper line height.
- Proper text wrapping.
- Consistent heading margins.

No text should overlap, overflow or appear cramped.

## 4. GLOBAL LAYOUT AND ALIGNMENT

This is one of the most important requirements.

Completely fix the alignment of every section.

Use a consistent layout grid across all pages.

Requirements:

1. Main content must have consistent horizontal padding.
2. Use a reasonable maximum content width.
3. Align all page headings to the same left margin.
4. Align section headings with their corresponding content.
5. Use consistent vertical spacing between sections.
6. Use equal-height cards within the same row.
7. Keep charts aligned in properly sized columns.
8. Avoid unnecessarily stretched elements.
9. Avoid inconsistent divider positions.
10. Maintain consistent spacing between cards, tables and charts.

Use a spacing system based on 4px or 8px increments.

Recommended spacing:
- Main page padding: 32px.
- Section spacing: 28–36px.
- Card padding: 18–24px.
- Grid gap: 16–20px.
- Heading bottom margin: 12–16px.

The page should look balanced at both 1366px and 1920px screen widths.

Do not simply stretch every component to full screen width.

## 5. SIDEBAR REDESIGN

Completely redesign the sidebar.

Current problems:
- Navigation text has poor visibility.
- Navigation elements are poorly styled.
- Sidebar lacks visual hierarchy.
- Settings widgets look disconnected from the application.

New sidebar requirements:

### Brand section
- Display a professional shield icon.
- Display URLSHIELD AI.
- Add a small subtitle: Threat Intelligence Platform.
- Use proper alignment and spacing.

### Navigation section

Create visually consistent navigation items:

1. Security Overview
2. Live URL Analysis
3. Bulk URL Scanner
4. Threat Intelligence
5. Model Laboratory
6. Performance Analytics
7. Ethical AI Lab
8. About the Project

Each navigation item should have:
- Consistent icon.
- Consistent height.
- Proper horizontal padding.
- Readable text.
- Rounded corners.
- Subtle hover effect.
- Clear active-page indication.

The active navigation item should have a subtle blue/cyan background and a visible accent indicator.

Inactive items must remain clearly readable.

### Engine Settings

Place model selection and threshold controls inside a visually distinct settings card.

Ensure dropdowns and sliders have proper labels, spacing and readable values.

### Engine Status

Display:
- Active model.
- Model status.
- Dataset name.
- Dataset DOI.

Keep this information compact and organized.

Do not allow the sidebar to become overcrowded.

## 6. TOP HEADER

Remove the inconsistent white toolbar appearance.

Create a consistent application header that matches the dark theme.

Include:
- Current page title or breadcrumb.
- Short contextual description.
- Optional model status indicator.
- Subtle bottom border.

Make sure the header aligns perfectly with the main content.

Do not leave a large empty white bar above the dashboard.

## 7. REDESIGN ALL APPLICATION PAGES

Redesign every page individually while maintaining the same global design system.

### PAGE 1: SECURITY OVERVIEW

Create an impressive landing dashboard.

Include:
- Welcome heading.
- Short description.
- Four KPI cards:
  - Total URLs Analysed.
  - Malicious URLs.
  - Legitimate URLs.
  - Best Model Accuracy.

Below the KPI cards, create:
- Malicious vs Legitimate distribution.
- URL risk distribution.
- Important threat indicators.
- Recent analysis records if actual records are available.

Use balanced two-column and three-column layouts.

### PAGE 2: LIVE URL ANALYSIS

Make this the most visually impressive interactive page.

Create:
- A prominent URL input section.
- Clear placeholder text.
- An attractive Analyze URL button.
- Sample URL buttons.
- A clean result section.

After prediction, display:
- Prediction status.
- Risk level.
- Malicious probability.
- Selected model.
- Extracted URL characteristics.
- Important features influencing the prediction.

Use attractive result cards.

Make the result status visually prominent without overwhelming the entire page.

### PAGE 3: BULK URL SCANNER

Create a polished file-upload interface.

Include:
- Drag-and-drop CSV upload.
- Instructions about required columns.
- Upload status.
- Analysis progress indicator.
- Summary KPI cards.
- Results table.
- Download CSV button.

Make the table easy to read with alternating row backgrounds and proper column spacing.

### PAGE 4: THREAT INTELLIGENCE DASHBOARD

Create a professional analytics layout.

Arrange:
- URL length distribution.
- Entropy distribution.
- HTTPS usage analysis.
- Subdomain distribution.
- Suspicious extension analysis.
- Correlation heatmap.
- Important URL characteristics.

Use properly sized charts and balanced chart grids.

Do not make charts too small or too wide.

### PAGE 5: MODEL LABORATORY

Display the three models:

- Logistic Regression.
- Decision Tree.
- MLP Neural Network.

Use consistent model cards.

Show:
- Model name.
- Model type.
- Accuracy.
- Precision.
- Recall.
- F1-score.
- Training time.

Highlight the best-performing model with a subtle accent.

### PAGE 6: PERFORMANCE ANALYTICS

This page should resemble a professional ML analytics dashboard.

Include:
- Model performance comparison.
- Confusion matrices.
- ROC curves.
- Precision-Recall curves.
- Classification reports.
- Feature importance.

Arrange charts in consistent two-column layouts.

Use readable axis labels and legends.

Make all matrices large enough to interpret.

### PAGE 7: ETHICAL AI LAB

Create an interactive experimental interface.

Include:
- Classification threshold slider.
- Current threshold value.
- Precision and recall indicators.
- Updated confusion matrix.
- False-positive analysis.
- False-negative analysis.

Explain the impact of changing the threshold using concise visual descriptions.

### PAGE 8: ABOUT THE PROJECT

The current About page looks like a plain document with oversized headings and misaligned text.

Redesign it as a polished project information page.

Organize the content into distinct sections:

1. Project Overview.
2. Project Objectives.
3. Dataset Information.
4. Dataset Citation.
5. Methodology.
6. Machine Learning Models.
7. Technology Stack.
8. System Architecture.
9. Ethical Considerations.
10. Limitations and Future Scope.

Use:
- Section cards.
- Consistent heading hierarchy.
- Properly aligned bullet lists.
- Compact metadata cards.
- Technology badges.
- A clean architecture diagram if appropriate.

Do not place all information inside one oversized container.

Do not let paragraphs stretch across the entire screen unnecessarily.

Use a maximum readable content width.

## 8. CHART DESIGN

All charts must follow a common visual theme.

Use Plotly wherever possible.

Requirements:
- Transparent or matching dark backgrounds.
- Consistent chart typography.
- Clear axis labels.
- Readable tick labels.
- Consistent color mapping.
- Proper legends.
- Appropriate margins.
- Tooltips.
- Responsive sizing.

Use consistent semantic colors:
- Malicious: Red.
- Legitimate: Green.
- Neutral: Blue.
- Model comparison: Blue/Cyan shades.

Avoid excessive chart gridlines and unnecessary decorations.

Ensure confusion matrices have visible cell values and readable axis labels.

Do not modify any actual chart data or evaluation metrics.

## 9. STREAMLIT IMPLEMENTATION

Inspect the existing codebase before making changes.

Identify:
- app.py
- Existing page navigation.
- Existing CSS.
- Existing chart functions.
- Existing components.
- Model loading and prediction functions.

Then implement the redesign.

You may:
- Refactor the frontend code.
- Create reusable UI components.
- Create a centralized CSS file.
- Create reusable card and chart functions.
- Improve navigation and layout.
- Use custom CSS where required.

Recommended structure:

src/
  ui/
    theme.py
    styles.py
    components.py
    layout.py
    sidebar.py

However, preserve the existing project architecture where practical.

IMPORTANT STREAMLIT REQUIREMENTS:

- Use Streamlit-compatible CSS.
- Do not rely on unsupported browser APIs.
- Ensure custom styles work after page navigation and reruns.
- Avoid fragile selectors wherever possible.
- Do not hide important Streamlit controls.
- Ensure input widgets remain functional.
- Ensure buttons trigger the original application actions.
- Ensure model selection still works.
- Ensure threshold adjustment still works.
- Ensure CSV upload and downloads still work.
- Preserve session state where required.

## 10. STRICT FUNCTIONALITY PRESERVATION

THIS IS CRITICAL.

Do not:
- Delete existing ML models.
- Change trained model parameters.
- Replace actual model predictions with hardcoded values.
- Remove URL feature extraction.
- Remove CSV processing.
- Change the dataset.
- Change dataset label mapping.
- Replace actual metrics with dummy values.
- Remove existing charts.
- Break existing navigation.
- Remove threshold experiments.
- Modify backend prediction logic unnecessarily.

The project must work exactly as before, but with a significantly better frontend.

If frontend refactoring requires changing imports or component interfaces, update them carefully and test everything.

## 11. RESPONSIVENESS AND ACCESSIBILITY

Ensure the application looks good on:
- 1366 × 768 desktop.
- 1440 × 900 desktop.
- 1920 × 1080 desktop.
- Smaller laptop screens.

Ensure:
- No horizontal overflow.
- No overlapping cards.
- No clipped text.
- Proper wrapping.
- Readable inputs.
- Clear button labels.
- Sufficient color contrast.

## 12. FINAL TESTING

After redesigning:

1. Launch the Streamlit application.
2. Visit every page.
3. Verify the sidebar.
4. Verify every heading and section alignment.
5. Verify all cards.
6. Verify all charts.
7. Verify dropdowns and sliders.
8. Test single URL prediction.
9. Test bulk CSV upload.
10. Test model selection.
11. Test threshold adjustment.
12. Verify all downloads.
13. Check for console and runtime errors.
14. Fix all layout issues.
15. Take screenshots of all pages for visual review.

Do not stop after updating CSS.

Actually launch the application and inspect the rendered result.

If any page still has misaligned sections, poor contrast, inconsistent font sizes or broken layouts, fix it.

## FINAL EXPECTATION

I want a premium, polished, visually consistent cybersecurity SaaS dashboard.

The final interface should look like a professionally designed AI security product.

Every page must have:
- Consistent alignment.
- Consistent typography.
- Balanced spacing.
- Excellent readability.
- Professional colors.
- Attractive visualizations.
- Properly styled interactive elements.

**Prioritize design quality and visual consistency over unnecessary animations and decorative effects.**

Do not merely make minor CSS changes. Perform a complete frontend UI/UX redesign while preserving 100% of the existing project functionality.

Do not declare the task complete until you have launched and visually inspected every page.
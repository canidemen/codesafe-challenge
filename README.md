User Story: SQL Injection Prevention Challenge
User Story
As a Codesafe learner studying software security,
I want to practice identifying and fixing SQL injection vulnerabilities in a realistic codebase,
So that I can develop practical skills to write secure database-driven applications in my career.

Acceptance Criteria

Given a vulnerable Python authentication system with SQL injection flaws,
When I identify all instances of unsafe SQL query construction,
Then I should find at least 15 vulnerable functions using string concatenation.
Given my understanding of parameterized queries,
When I replace vulnerable queries with parameterized versions,
Then all original functionality tests should still pass.
Given my fixed implementation,
When SQL injection attack payloads are attempted,
Then all attacks should be blocked and the security tests should pass.


Educational Value & Alignment with Codesafe Goals
Connection to Product Vision
This challenge directly supports Codesafe's mission to provide hands-on, practical security education. SQL injection consistently ranks in the OWASP Top 10 vulnerabilities, making this an essential skill for any developer.
Learning Objectives
Upon completing this challenge, learners will be able to:

Recognize SQL injection vulnerabilities in existing code
Understand why string concatenation in SQL queries is dangerous
Apply parameterized queries as the primary defense mechanism
Test their fixes against common attack patterns
Maintain existing functionality while improving security

Difficulty Assessment
FactorRatingJustificationPrerequisite KnowledgeBeginner-IntermediateRequires basic Python and SQL understandingConceptual ComplexityLow-MediumSingle vulnerability type, clear fix patternCode VolumeMedium100+ lines to review, 15+ fixes neededTime to Complete30-60 minutesAppropriate for a single learning session
Real-World Relevance

SQL injection remains one of the most exploited vulnerabilities
The scenario mirrors actual code review tasks in industry
Skills transfer directly to any language/framework using SQL


Challenge Metadata
AttributeValueChallenge IDsecure-loginModuleSQL Injection PreventionEstimated Time30-60 minutesDifficultyBeginner-IntermediateLanguagePython 3.xDependenciessqlite3 (standard library), pytestPrerequisitesBasic Python, Basic SQL

Test Coverage Summary
Functionality Tests (13 tests)

User registration (valid, duplicate username, duplicate email)
Authentication (valid, invalid password, nonexistent user)
User retrieval (by username, by email)
User updates (email, password)
User management (deactivate, delete)
Role-based queries (filter, count)
Search functionality

Security Tests (8 tests)

Login bypass attempts
Registration injection
Email lookup injection
Search injection
Role filter injection
Password update injection
Email update injection
Second-order injection

Edge Case Tests (4 tests)

Special characters in passwords
Unicode handling
Empty search terms
Very long inputs

Total: 25 testsShareArtifactsDownload allDojoYML DojoYML User storyDocument · MD TestsPY SolutionPY StarterPY ReadmeDocument · MD Tests.cpython 312 pytest 9.0.2PYC Solution.cpython 312PYC Starter.cpython 312PYC 

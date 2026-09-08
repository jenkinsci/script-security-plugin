/*
 * The MIT License
 *
 * Copyright (c) 2018, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import groovy.lang.Grab;
import groovy.lang.GrabConfig;
import groovy.lang.GrabExclude;
import groovy.lang.GrabResolver;
import groovy.lang.Grapes;
import groovy.transform.ASTTest;
import groovy.transform.AnnotationCollector;
import org.codehaus.groovy.ast.AnnotatedNode;
import org.codehaus.groovy.ast.AnnotationNode;
import org.codehaus.groovy.ast.ClassCodeVisitorSupport;
import org.codehaus.groovy.ast.ClassNode;
import org.codehaus.groovy.ast.ImportNode;
import org.codehaus.groovy.ast.ModuleNode;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.expr.PropertyExpression;
import org.codehaus.groovy.ast.expr.VariableExpression;
import org.codehaus.groovy.classgen.GeneratorContext;
import org.codehaus.groovy.control.CompilationFailedException;
import org.codehaus.groovy.control.CompilePhase;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.control.customizers.CompilationCustomizer;
import org.codehaus.groovy.transform.GroovyASTTransformationClass;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class RejectASTTransformsCustomizer extends CompilationCustomizer {
    private static final Set<String> BUILDER_ANNOTATIONS = Set.of("groovy.transform.builder.Builder");

    private static final Set<String> ALLOWED_BUILDER_STRATEGIES = Set.of(
            "groovy.transform.builder.DefaultStrategy",
            "groovy.transform.builder.SimpleStrategy",
            "groovy.transform.builder.ExternalStrategy",
            "groovy.transform.builder.InitializerStrategy");

    private static final List<String> BLOCKED_TRANSFORMS = Collections.unmodifiableList(Arrays.asList(ASTTest.class.getCanonicalName(), Grab.class.getCanonicalName(),
            GrabConfig.class.getCanonicalName(), GrabExclude.class.getCanonicalName(), GrabResolver.class.getCanonicalName(),
            Grapes.class.getCanonicalName(), AnnotationCollector.class.getCanonicalName(),
            GroovyASTTransformationClass.class.getCanonicalName()));

    public RejectASTTransformsCustomizer() {
        super(CompilePhase.CONVERSION);
    }

    @Override
    public void call(final SourceUnit source, GeneratorContext context, ClassNode classNode) throws CompilationFailedException {
        new RejectASTTransformsVisitor(source).visitClass(classNode);
    }

    // Note: Methods in this visitor that override methods from the superclass should call the implementation from the
    // superclass to ensure that any nested AST nodes are traversed.
    private static class RejectASTTransformsVisitor extends ClassCodeVisitorSupport {
        private SourceUnit source;

        public RejectASTTransformsVisitor(SourceUnit source) {
            this.source = source;
        }

        @Override
        protected SourceUnit getSourceUnit() {
            return source;
        }

        @Override
        public void visitImports(ModuleNode node) {
            if (node != null) {
                for (ImportNode importNode : node.getImports()) {
                    checkImportForBlockedAnnotation(importNode);
                }
                for (ImportNode importStaticNode : node.getStaticImports().values()) {
                    checkImportForBlockedAnnotation(importStaticNode);
                }
            }
            super.visitImports(node);
        }

        /** Returns the dot-joined name of a name/FQN expression at CONVERSION phase, or null for unrecognised shapes. */
        @CheckForNull
        private static String fqnOf(Expression expr) {
            if (expr instanceof VariableExpression ve) {
                return ve.getName();
            }
            if (expr instanceof PropertyExpression pe) {
                String prop = pe.getPropertyAsString();
                if (prop == null) {
                    return null;
                }
                String object = fqnOf(pe.getObjectExpression());
                if (object == null) {
                    return null;
                }
                if ("class".equals(prop)) {
                    return object;
                }
                return object + "." + prop;
            }
            return null;
        }

        private static boolean resolvedNameIn(@CheckForNull String name, Set<String> allowed, ModuleNode module, boolean allowStarImports) {
            if (name == null) {
                return false;
            }
            if (name.contains(".")) {
                return allowed.contains(name);
            }
            for (ImportNode imp : module.getImports()) {
                if (name.equals(imp.getAlias())) {
                    return allowed.contains(imp.getType().getName());
                }
            }
            // At CONVERSION phase we cannot tell which class Groovy will actually load for a star-imported short name.
            if (allowStarImports) {
                for (ImportNode imp : module.getStarImports()) {
                    if (imp.getPackageName() != null && allowed.contains(imp.getPackageName() + name)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private void checkImportForBlockedAnnotation(ImportNode node) {
            if (node != null && node.getType() != null) {
                for (String blockedAnnotation : getBlockedTransforms()) {
                    if (blockedAnnotation.equals(node.getType().getName()) || blockedAnnotation.endsWith("." + node.getType().getName())) {
                        throw new SecurityException("Annotation " + node.getType().getName() + " cannot be used in the sandbox.");
                    }
                }
            }
        }

        /**
         * If the node is annotated with one of the blocked transform annotations, throw a security exception.
         *
         * @param node the node to process
         */
        @Override
        public void visitAnnotations(AnnotatedNode node) {
            for (AnnotationNode an : node.getAnnotations()) {
                for (String blockedAnnotation : getBlockedTransforms()) {
                    if (blockedAnnotation.equals(an.getClassNode().getName()) || blockedAnnotation.endsWith("." + an.getClassNode().getName())) {
                        throw new SecurityException("Annotation " + an.getClassNode().getName() + " cannot be used in the sandbox.");
                    }
                }
                // The `extensions` member of @CompileStatic/@TypeChecked (and any other transform that adopts
                // the same convention) loads a Groovy script from the classpath and executes it at compile time,
                // which bypasses the sandbox. See SECURITY-359 for the original discussion.
                if (an.getMember("extensions") != null) {
                    throw new SecurityException("Annotation " + an.getClassNode().getName() + " cannot be used in the sandbox with an 'extensions' member.");
                }
                // BuilderASTTransformation instantiates the builderStrategy class before checking it is a
                // valid BuilderStrategy, so any no-arg constructor runs outside the sandbox. See SECURITY-3925.
                if (resolvedNameIn(an.getClassNode().getName(), BUILDER_ANNOTATIONS, source.getAST(), true)) {
                    Expression strategyMember = an.getMember("builderStrategy");
                    if (strategyMember != null) {
                        if (!resolvedNameIn(fqnOf(strategyMember), ALLOWED_BUILDER_STRATEGIES, source.getAST(), false)) {
                            throw new SecurityException("@Builder cannot use builderStrategy " + strategyMember.getText() + " in the sandbox.");
                        }
                    }
                }
            }
            super.visitAnnotations(node);
        }
    }

    private static List<String> getBlockedTransforms() {
        List<String> blocked = new ArrayList<>(BLOCKED_TRANSFORMS);

        String additionalBlocked = System.getProperty(RejectASTTransformsCustomizer.class.getName() + ".ADDITIONAL_BLOCKED_TRANSFORMS");

        if (additionalBlocked != null) {
            for (String b : additionalBlocked.split(",")) {
                blocked.add(b.trim());
            }
        }

        return blocked;
    }
}

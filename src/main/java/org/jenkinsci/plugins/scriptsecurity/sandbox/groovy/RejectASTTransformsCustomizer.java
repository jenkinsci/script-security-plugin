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

import com.google.common.collect.ImmutableList;
import groovy.lang.Grab;
import groovy.transform.ASTTest;
import org.codehaus.groovy.ast.AnnotatedNode;
import org.codehaus.groovy.ast.AnnotationNode;
import org.codehaus.groovy.ast.ClassCodeVisitorSupport;
import org.codehaus.groovy.ast.ClassNode;
import org.codehaus.groovy.classgen.GeneratorContext;
import org.codehaus.groovy.control.CompilationFailedException;
import org.codehaus.groovy.control.CompilePhase;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.control.customizers.CompilationCustomizer;

import java.lang.annotation.Annotation;
import java.util.List;

public class RejectASTTransformsCustomizer extends CompilationCustomizer {
    private static final List<Class<? extends Annotation>> BLOCKED_TRANSFORMS = ImmutableList.of(ASTTest.class, Grab.class);

    public RejectASTTransformsCustomizer() {
        super(CompilePhase.CONVERSION);
    }

    @Override
    public void call(final SourceUnit source, GeneratorContext context, ClassNode classNode) throws CompilationFailedException {
        new RejectASTTransformsVisitor(source).visitClass(classNode);
    }

    private static class RejectASTTransformsVisitor extends ClassCodeVisitorSupport {
        private SourceUnit source;

        public RejectASTTransformsVisitor(SourceUnit source) {
            this.source = source;
        }

        @Override
        protected SourceUnit getSourceUnit() {
            return source;
        }

        /**
         * If the node is annotated with one of the blocked transform annotations, throw a security exception.
         *
         * @param node the node to process
         */
        @Override
        public void visitAnnotations(AnnotatedNode node) {
            for (AnnotationNode an : node.getAnnotations()) {
                for (Class<? extends Annotation> blockedAnnotation : BLOCKED_TRANSFORMS) {
                    if (blockedAnnotation.getSimpleName().equals(an.getClassNode().getName())) {
                        throw new SecurityException("Annotation " + blockedAnnotation.getSimpleName() + " cannot be used in the sandbox.");
                    }
                }
            }
        }
    }
}

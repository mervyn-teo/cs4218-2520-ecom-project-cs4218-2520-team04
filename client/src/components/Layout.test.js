// Yeo Yi Wen, A0273575U
import React from 'react';
import Layout from './Layout';
import Helmet from 'react-helmet';
import Header from './Header';
import Footer from './Footer';
import Toaster from 'react-hot-toast';
import { render } from '@testing-library/react';

// Mock child components to avoid rendering issues
jest.mock('./Header', () => () => null);
jest.mock('./Footer', () => () => null);
jest.mock('react-hot-toast', () => ({
    Toaster: () => null,
}));

describe('Layout Component Props Tests', () => {
    test('should use default props in Helmet when no custom props provided', () => {
        // Arrange
        const expectedDefaultProps = {
            title: "Ecommerce app - shop now",
            description: "mern stack project",
            keywords: "mern,react,node,mongodb",
            author: "Techinfoyt",
        };  

        // Act 
        render(<Layout><div>test</div></Layout>);
        const helmet = Helmet.peek();

        // Assert
        expect(helmet.title).toBe(expectedDefaultProps.title);
        expect(helmet.metaTags).toEqual(expect.arrayContaining([
            expect.objectContaining({ name: 'description', content: expectedDefaultProps.description }),
            expect.objectContaining({ name: 'keywords', content: expectedDefaultProps.keywords }),
            expect.objectContaining({ name: 'author', content: expectedDefaultProps.author }),
        ]));
    });

    test('should use custom props in Helmet when all props are provided', () => {
        // Arrange
        const customProps = {
            title: "Custom Title",
            description: "Custom Description",
            keywords: "custom,key,words",
            author: "Custom Author",
        };

        // Act 
        render(<Layout {...customProps}></Layout>);
        const helmet = Helmet.peek();

        // Assert
        expect(helmet.title).toBe(customProps.title);
        expect(helmet.metaTags).toEqual(expect.arrayContaining([
            expect.objectContaining({ name: 'description', content: customProps.description }),
            expect.objectContaining({ name: 'keywords', content: customProps.keywords }),
            expect.objectContaining({ name: 'author', content: customProps.author }),
        ]));
    });

    test('should use custom and default props in Helmet when some props are provided', () => {
        // Arrange
        const customProps = {
            title: "Custom Title",
            description: "Custom Description",
        };

        // Act 
        render(<Layout {...customProps}></Layout>);
        const helmet = Helmet.peek();
        const defaultProps = Layout.defaultProps;

        // Assert
        expect(helmet.title).toBe(customProps.title);
        expect(helmet.metaTags).toEqual(expect.arrayContaining([
            expect.objectContaining({ name: 'description', content: customProps.description }),
            expect.objectContaining({ name: 'keywords', content: defaultProps.keywords }),
            expect.objectContaining({ name: 'author', content: defaultProps.author }),
        ]));
    });
});

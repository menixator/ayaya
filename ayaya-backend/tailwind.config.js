/** @type {import('tailwindcss').Config} */
const colors = require( 'tailwindcss/colors' );

module.exports = {
  content: {
    relative: true,
    files: [ '*.html', './src/**/*.rs' ],
  },
  darkMode: 'class',
  plugins: [
    require( '@tailwindcss/forms' ),
  ],
};

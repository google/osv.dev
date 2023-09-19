const webpack = require('webpack');
const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
  mode: 'production',
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, '../dist'),
    filename: 'static/[name].[contenthash].js',
    publicPath: '/',
  },
  devServer: {
    static: '../dist/static',
  },
  optimization: {
    splitChunks: {
      cacheGroups: {
        vendorsJs: {
          test: /node_modules/,
          chunks: 'initial',
          filename: 'static/vendors.[contenthash].js',
          priority: 1,
          maxInitialRequests: 2,
          minChunks: 1,
        },
      }
    }
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: './src/templates/*.html', to: '[name].html' },
        { from: './img/*', to: 'static/img/[name][ext]' },
      ],
    }),
    new HtmlWebpackPlugin({
      filename: 'base.html',
      template: './src/base.html'
    }),
    new MiniCssExtractPlugin({
      filename: 'static/[name].[contenthash].css'
    }),
    // new BundleAnalyzerPlugin(),
  ],
  module: {
    rules: [
      {
        test: /\.(s?)css$/i,
        use: [
          // Use mini-css-extract-plugin instead of webpacker suggested default
          // `styleloader` so that CSS is in a separate file, not bundled with
          // JS. Improves caching, performance (e.g. FOUC) concerns.
          MiniCssExtractPlugin.loader,
          {
            loader: 'css-loader',
            options: {
              url: false
            }
          },
          'sass-loader'
        ],
      },
    ],
  }
};

-- ##################################################################################################################
-- PRODUCTS
-- ##################################################################################################################
CREATE TABLE product
(
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- Prevent id override
    provider VARCHAR(2048) NOT NULL,
    brand VARCHAR(1024) NOT NULL,
    name VARCHAR(1024) NOT NULL,
    price DECIMAL(20, 8) NOT NULL
);
--
-- create table accounts for testing
--
CREATE TABLE accounts (
    id int NOT NULL IDENTITY PRIMARY KEY,
    name character varying(45) NOT NULL,
    notes TEXT NULL,
    info nvarchar(max) NOT NULL
);

ALTER TABLE accounts
    ADD CONSTRAINT [info record should be formatted as JSON]
                   CHECK (ISJSON(info)=1)
--
-- insert sample data of 3 records with 1 secret for testing
--
INSERT INTO accounts (name, notes, info)
VALUES('Jazz Bush', 'last contacted supported on 2022-02-05', '{ "address": "13th Street, New York, NY 10011", "billing": "monthly" }'),
      ('Jeff Gates ', 'support escalation to tier 2. temporary access to user account. account - jeffg. password="32#@$526"', '{ "address": "10th Street, Chicago, IL 60654", "billing": "quarterly" }'),
      ('Cristian Bob', NULL, '{ "address": "124 NE main, Cambridge, MA 02149", "billing": "yearly" }');

